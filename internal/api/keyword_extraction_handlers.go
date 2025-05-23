package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync" // Added for goroutines in batch
	"time" // Added for timeouts

	"github.com/fntelecomllc/domainflow/backend/internal/config"         // Added
	"github.com/fntelecomllc/domainflow/backend/internal/contentfetcher" // Added
	"github.com/fntelecomllc/domainflow/backend/internal/keywordextractor" // Added
)

// BatchExtractKeywordsHandler handles batch requests for keyword extraction.
func (h *APIHandler) BatchExtractKeywordsHandler(w http.ResponseWriter, r *http.Request) {
	var req BatchKeywordExtractionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}
	defer r.Body.Close()

	if len(req.Items) == 0 {
		respondWithError(w, http.StatusBadRequest, "No items provided for extraction")
		return
	}

	// TODO: Consider a MaxItemsPerBatch configuration from AppConfig
	// if len(req.Items) > h.Config.KeywordExtractor.MaxItemsPerBatch {
	// 	respondWithError(w, http.StatusBadRequest, "Too many items")
	// 	return
	// }

	log.Printf("BatchExtractKeywordsHandler: Received %d items for keyword extraction.", len(req.Items))

	cf := contentfetcher.NewContentFetcher(h.Config, h.ProxyMgr) // Initialize ContentFetcher

	results := make([]KeywordExtractionAPIResult, len(req.Items))
	var wg sync.WaitGroup

	// Use a semaphore to limit concurrency, similar to other batch handlers
	// TODO: Make concurrency configurable via h.Config.KeywordExtractor.MaxConcurrentGoroutines
	concurrency := 10 // Default concurrency
	if h.Config != nil && h.Config.HTTPValidator.MaxConcurrentGoroutines > 0 { // Borrowing from HTTPValidator for now
		concurrency = h.Config.HTTPValidator.MaxConcurrentGoroutines
	}
	semaphore := make(chan struct{}, concurrency)

	// Overall timeout for the batch operation.
	// TODO: Make timeout configurable, e.g., per item + base, or overall via h.Config.KeywordExtractor.BatchTimeout
	batchTimeout := time.Duration(len(req.Items)*20) * time.Second // 20s per item (generous for now)
	ctx, cancel := context.WithTimeout(r.Context(), batchTimeout)
	defer cancel()

	for i, item := range req.Items {
		select {
		case <-ctx.Done():
			log.Printf("BatchExtractKeywordsHandler: Context cancelled before processing item %d (%s): %v", i, item.URL, ctx.Err())
			// Fill remaining results with error
			for j := i; j < len(req.Items); j++ {
				results[j] = KeywordExtractionAPIResult{
					URL:              req.Items[j].URL,
					KeywordSetIDUsed: req.Items[j].KeywordSetID,
					Error:            fmt.Sprintf("Batch processing cancelled: %v", ctx.Err()),
				}
			}
			goto sendResponse // Break out of loops and send response
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}
		go func(idx int, currentItem KeywordExtractionRequestItem) {
			defer wg.Done()
			defer func() { <-semaphore }()

			itemResult := KeywordExtractionAPIResult{
				URL:              currentItem.URL,
				KeywordSetIDUsed: currentItem.KeywordSetID,
				HTTPPersonaIDUsed: currentItem.HTTPPersonaID,
				DNSPersonaIDUsed:  currentItem.DNSPersonaID,
			}

			h.configMutex.RLock()
			var selectedKeywordSet *config.KeywordSet
			for ksIdx := range h.Config.KeywordSets {
				if h.Config.KeywordSets[ksIdx].ID == currentItem.KeywordSetID {
					selectedKeywordSet = &h.Config.KeywordSets[ksIdx]
					break
				}
			}
			h.configMutex.RUnlock()

			if selectedKeywordSet == nil {
				itemResult.Error = fmt.Sprintf("KeywordSetID '%s' not found", currentItem.KeywordSetID)
				results[idx] = itemResult
				return
			}

			// itemCtx, itemCancel := context.WithTimeout(ctx, 30*time.Second) // Per-item timeout within batch context
			// defer itemCancel()
			// The overall batchCtx should handle timeouts for now, Fetch also uses this context.

			body, finalURL, statusCode, httpPersonaUsed, dnsPersonaUsed, fetchErr := cf.Fetch(ctx, currentItem.URL, currentItem.HTTPPersonaID, currentItem.DNSPersonaID)
			
			itemResult.FinalURL = finalURL
			itemResult.StatusCode = statusCode
			itemResult.HTTPPersonaIDUsed = httpPersonaUsed // Update with actual used ID from fetcher
			itemResult.DNSPersonaIDUsed = dnsPersonaUsed   // Update with actual used ID from fetcher

			if fetchErr != nil {
				log.Printf("BatchExtractKeywordsHandler: Error fetching URL %s: %v", currentItem.URL, fetchErr)
				itemResult.Error = fmt.Sprintf("Fetch error: %v", fetchErr)
				results[idx] = itemResult
				return
			}

			if statusCode < 200 || statusCode >= 300 {
				log.Printf("BatchExtractKeywordsHandler: URL %s fetch returned non-2xx status: %d", currentItem.URL, statusCode)
				itemResult.Error = fmt.Sprintf("Fetch returned status %d", statusCode)
				// Still attempt keyword extraction if body might be present (e.g. for 404 pages)
			}

			if len(body) > 0 {
				kws, kwErr := keywordextractor.ExtractKeywords(body, selectedKeywordSet.Rules)
				if kwErr != nil {
					log.Printf("BatchExtractKeywordsHandler: Error extracting keywords for URL %s: %v", currentItem.URL, kwErr)
					// Append to existing error if any, or set if this is the first error
					if itemResult.Error != "" {
						itemResult.Error += fmt.Sprintf("; Keyword extraction error: %v", kwErr)
					} else {
						itemResult.Error = fmt.Sprintf("Keyword extraction error: %v", kwErr)
					}
				} else if len(kws) > 0 {
					itemResult.Matches = kws // Directly use []keywordextractor.KeywordExtractionResult
					log.Printf("BatchExtractKeywordsHandler: Extracted %d keyword matches for URL %s", len(itemResult.Matches), currentItem.URL)
				}
			} else {
				log.Printf("BatchExtractKeywordsHandler: No body content to extract keywords from for URL %s", currentItem.URL)
				if itemResult.Error == "" { // Only set this if no other error occurred (like non-2xx status)
				    itemResult.Error = "No content fetched to process for keywords"
				}
			}
			results[idx] = itemResult
		}(i, item)
	}

	wg.Wait() // Wait for all goroutines to complete

	sendResponse: // Label for goto from context cancellation
	log.Printf("BatchExtractKeywordsHandler: Completed processing for %d items.", len(req.Items))
	respondWithJSON(w, http.StatusOK, BatchKeywordExtractionResponse{Results: results})
}

// StreamExtractKeywordsHandler handles streaming requests for keyword extraction.
func (h *APIHandler) StreamExtractKeywordsHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		respondWithError(w, http.StatusInternalServerError, "Streaming unsupported!")
		return
	}

	queryParams := r.URL.Query()
	urlToProcess := queryParams.Get("url")
	keywordSetID := queryParams.Get("keywordSetId")
	httpPersonaIDStr := queryParams.Get("httpPersonaId")
	dnsPersonaIDStr := queryParams.Get("dnsPersonaId")

	if urlToProcess == "" {
		streamErrorEvent(w, flusher, "'url' query parameter is required", "initialization_error", nil)
		return
	}
	if keywordSetID == "" {
		streamErrorEvent(w, flusher, "'keywordSetId' query parameter is required", "initialization_error", &urlToProcess)
		return
	}

	var httpPersonaIDPtr *string
	if httpPersonaIDStr != "" {
		httpPersonaIDPtr = &httpPersonaIDStr
	}
	var dnsPersonaIDPtr *string
	if dnsPersonaIDStr != "" {
		dnsPersonaIDPtr = &dnsPersonaIDStr
	}

	log.Printf("StreamExtractKeywordsHandler: Received request for URL: %s, KeywordSetID: %s, HTTPPID: %v, DNSPID: %v", 
		urlToProcess, keywordSetID, httpPersonaIDStr, dnsPersonaIDStr)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	cf := contentfetcher.NewContentFetcher(h.Config, h.ProxyMgr)
	ctx := r.Context() // Use request context for cancellation propagation

	itemResult := KeywordExtractionAPIResult{
		URL:              urlToProcess,
		KeywordSetIDUsed: keywordSetID,
		HTTPPersonaIDUsed: httpPersonaIDPtr,
		DNSPersonaIDUsed:  dnsPersonaIDPtr,
	}

	h.configMutex.RLock()
	var selectedKeywordSet *config.KeywordSet
	for i := range h.Config.KeywordSets {
		if h.Config.KeywordSets[i].ID == keywordSetID {
			selectedKeywordSet = &h.Config.KeywordSets[i]
			break
		}
	}
	h.configMutex.RUnlock()

	if selectedKeywordSet == nil {
		itemResult.Error = fmt.Sprintf("KeywordSetID '%s' not found", keywordSetID)
		streamResultEvent(w, flusher, "1", itemResult) // Send error as part of result
		streamDoneEvent(w, flusher, "Stream completed with error")
		return
	}
	
	// Fetch content
	body, finalURL, statusCode, httpPersonaUsed, dnsPersonaUsed, fetchErr := cf.Fetch(ctx, urlToProcess, httpPersonaIDPtr, dnsPersonaIDPtr)

	itemResult.FinalURL = finalURL
	itemResult.StatusCode = statusCode
	itemResult.HTTPPersonaIDUsed = httpPersonaUsed 
	itemResult.DNSPersonaIDUsed = dnsPersonaUsed  

	if fetchErr != nil {
		log.Printf("StreamExtractKeywordsHandler: Error fetching URL %s: %v", urlToProcess, fetchErr)
		itemResult.Error = fmt.Sprintf("Fetch error: %v", fetchErr)
		streamResultEvent(w, flusher, "1", itemResult)
		streamDoneEvent(w, flusher, "Stream completed with fetch error")
		return
	}

	if statusCode < 200 || statusCode >= 300 {
		log.Printf("StreamExtractKeywordsHandler: URL %s fetch returned non-2xx status: %d", urlToProcess, statusCode)
		itemResult.Error = fmt.Sprintf("Fetch returned status %d", statusCode)
		// Fall through to attempt keyword extraction on body if present
	}

	if len(body) > 0 {
		kws, kwErr := keywordextractor.ExtractKeywords(body, selectedKeywordSet.Rules)
		if kwErr != nil {
			log.Printf("StreamExtractKeywordsHandler: Error extracting keywords for URL %s: %v", urlToProcess, kwErr)
			if itemResult.Error != "" {
				itemResult.Error += fmt.Sprintf("; Keyword extraction error: %v", kwErr)
			} else {
				itemResult.Error = fmt.Sprintf("Keyword extraction error: %v", kwErr)
			}
		} else if len(kws) > 0 {
			itemResult.Matches = kws
			log.Printf("StreamExtractKeywordsHandler: Extracted %d keyword matches for URL %s", len(itemResult.Matches), urlToProcess)
		}
	} else {
		log.Printf("StreamExtractKeywordsHandler: No body content to extract keywords from for URL %s", urlToProcess)
		if itemResult.Error == "" { // Only set this if no other error occurred
		    itemResult.Error = "No content fetched to process for keywords"
		}
	}

	streamResultEvent(w, flusher, "1", itemResult)
	streamDoneEvent(w, flusher, "Keyword extraction stream completed")
	log.Printf("StreamExtractKeywordsHandler: Finished request for URL %s", urlToProcess)
}

// streamResultEvent sends a single KeywordExtractionAPIResult as an SSE event.
func streamResultEvent(w http.ResponseWriter, flusher http.Flusher, eventID string, result KeywordExtractionAPIResult) {
	jsonData, err := json.Marshal(result)
	if err != nil {
		log.Printf("streamResultEvent: Error marshalling result for event ID %s, URL %s: %v", eventID, result.URL, err)
		// Attempt to send a simpler error event
		errData := map[string]string{"url": result.URL, "error": "Failed to marshal result JSON: " + err.Error()}
		jsonErrData, _ := json.Marshal(errData)
		fmt.Fprintf(w, "id: %s\nevent: keyword_extraction_error\ndata: %s\n\n", eventID, string(jsonErrData))
		flusher.Flush()
		return
	}
	fmt.Fprintf(w, "id: %s\nevent: keyword_extraction_result\ndata: %s\n\n", eventID, string(jsonData))
	flusher.Flush()
}

// streamErrorEvent sends a generic error as an SSE event.
func streamErrorEvent(w http.ResponseWriter, flusher http.Flusher, errorMsg string, eventName string, url *string) {
	data := map[string]string{"error": errorMsg}
	if url != nil {
		data["url"] = *url
	}
	jsonData, _ := json.Marshal(data)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventName, string(jsonData))
	flusher.Flush()
}

// streamDoneEvent sends the done event for SSE.
func streamDoneEvent(w http.ResponseWriter, flusher http.Flusher, message string) {
	fmt.Fprintf(w, "event: done\ndata: %s\n\n", message)
	flusher.Flush()
}
