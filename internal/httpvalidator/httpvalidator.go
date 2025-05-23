// File: backend/internal/httpvalidator/httpvalidator.go
package httpvalidator

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/sha256"
	// "crypto/tls" // REMOVED - TLS configuration is handled by the client passed in
	"fmt"
	"io"
	"io/ioutil"
	"log"
	// "math/rand" // REMOVED - User-Agent selection is handled by caller
	"net/http"
	// "net/http/cookiejar" // REMOVED - Cookie jar is part of the client passed in
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	// Corrected import: removed "proxyutils" alias
	"github.com/fntelecomllc/domainflow/backend/internal/config"
	"golang.org/x/net/html/charset"
)

const maxBodyReadBytes = 2 * 1024 * 1024

type HTTPValidator struct {
	defaultConfig config.HTTPValidatorConfig // Stores default server HTTP settings
}

func New(cfg config.HTTPValidatorConfig) *HTTPValidator {
	return &HTTPValidator{
		defaultConfig: cfg,
	}
}

// ValidateDomainsWithClient is used by the BATCH handler.
// It processes a batch of domains using a single, pre-configured client.
func (hv *HTTPValidator) ValidateDomainsWithClient(
	domains []string,
	httpClient *http.Client,
	userAgent string,
	headers map[string]string,
	// maxRedirects int, // This is now part of the httpClient's CheckRedirect policy
	ctx context.Context,
) []ValidationResult {
	results := make([]ValidationResult, len(domains))
	var wg sync.WaitGroup

	concurrency := hv.defaultConfig.MaxConcurrentGoroutines
	if concurrency <= 0 {
		concurrency = 10
	}
	semaphore := make(chan struct{}, concurrency)

	for i, domain := range domains {
		select {
		case <-ctx.Done():
			log.Printf("HTTPValidator Batch: Context cancelled before processing domain %s", domain)
			for j := i; j < len(domains); j++ {
				results[j] = ValidationResult{Domain: domains[j], Status: "Cancelled", Error: "Batch context cancelled", Timestamp: time.Now().Format(time.RFC3339)}
			}
			goto endBatchLoop
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}
		go func(idx int, d string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			domainCtx, domainCancel := context.WithCancel(ctx)
			defer domainCancel()

			select {
			case <-domainCtx.Done():
				results[idx] = ValidationResult{Domain: d, Status: "Cancelled", Error: "Context cancelled before validation", Timestamp: time.Now().Format(time.RFC3339)}
				return
			default:
			}
			results[idx] = hv.validateSingleDomain(domainCtx, d, httpClient, userAgent, headers)
		}(i, domain)
	}
endBatchLoop:
	wg.Wait()
	return results
}

// ValidateSingleDomainWithClient is used by the STREAM handler.
func (hv *HTTPValidator) ValidateSingleDomainWithClient(
	domain string,
	httpClient *http.Client,
	userAgent string,
	headers map[string]string,
	// maxRedirects int, // Part of httpClient
	ctx context.Context,
) ValidationResult {
	return hv.validateSingleDomain(ctx, domain, httpClient, userAgent, headers)
}

func (hv *HTTPValidator) validateSingleDomain(
	ctx context.Context,
	domain string,
	client *http.Client,
	ua string,
	customHeaders map[string]string,
) ValidationResult {
	startTime := time.Now()
	result := ValidationResult{
		Domain:    domain,
		Timestamp: startTime.Format(time.RFC3339),
	}

	targetURL := domain
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	var urlsToTry []string
	if strings.HasPrefix(targetURL, "http://") {
		urlsToTry = append(urlsToTry, targetURL, strings.Replace(targetURL, "http://", "https://", 1))
	} else {
		urlsToTry = append(urlsToTry, targetURL)
	}

	var lastError error
	var resp *http.Response
	var attemptURL string

	for _, rawURL := range urlsToTry {
		select {
		case <-ctx.Done():
			result.Status = "Cancelled"
			result.Error = "Context cancelled before HTTP attempt: " + ctx.Err().Error()
			result.DurationMs = time.Since(startTime).Milliseconds()
			return result
		default:
		}
		attemptURL = rawURL

		parsedURL, err := url.Parse(attemptURL)
		if err != nil {
			lastError = fmt.Errorf("invalid URL %s: %w", attemptURL, err)
			continue
		}

		req, err := http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
		if err != nil {
			lastError = fmt.Errorf("failed to create request for %s: %w", attemptURL, err)
			if resp != nil { // Should be currentResp if this was in a loop before assignment
				io.Copy(ioutil.Discard, resp.Body) // Ensure body is closed if err after resp
				resp.Body.Close()
			}
			continue
		}

		req.Header.Set("User-Agent", ua)
		for key, value := range customHeaders {
			req.Header.Set(key, value)
		}

		currentResp, doErr := client.Do(req) // Renamed err to doErr
		if doErr != nil {
			lastError = fmt.Errorf("request to %s failed: %w", attemptURL, doErr)
			// if urlErr, ok := doErr.(*url.Error); ok && urlErr.Timeout() { /* log.Printf("HTTPValidator: Timeout to %s", attemptURL) */ }
			if currentResp != nil {
				io.Copy(ioutil.Discard, currentResp.Body)
				currentResp.Body.Close()
			}
			if ctx.Err() == context.Canceled || ctx.Err() == context.DeadlineExceeded {
				result.Status = "Cancelled"
				result.Error = lastError.Error() + " (context: " + ctx.Err().Error() + ")"
				result.DurationMs = time.Since(startTime).Milliseconds()
				return result
			}
			continue
		}

		resp = currentResp // Assign currentResp to resp only on success
		lastError = nil
		break
	}

	result.DurationMs = time.Since(startTime).Milliseconds()

	if lastError != nil {
		result.Status = "Error"
		result.Error = lastError.Error()
		if strings.Contains(strings.ToLower(lastError.Error()), "redirect") { // Simplistic check
			result.Status = "Redirect Limit Reached"
		}
		if urlErr, ok := lastError.(*url.Error); ok && urlErr.Timeout() {
			result.Status = "Timeout"
		}
		if ctx.Err() == context.Canceled || ctx.Err() == context.DeadlineExceeded {
			result.Status = "Cancelled"
			result.Error = result.Error + " (context: " + ctx.Err().Error() + ")"
		}
		return result
	}
	if resp == nil {
		result.Status = "Error"
		result.Error = "No response received (tried: " + strings.Join(urlsToTry, ", ") + ")"
		return result
	}
	defer func() {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}()

	result.FinalURL = resp.Request.URL.String()
	result.StatusCode = resp.StatusCode
	result.Status = http.StatusText(resp.StatusCode)
	if result.Status == "" {
		result.Status = fmt.Sprintf("Status %d", resp.StatusCode)
	}

	result.ResponseHeaders = make(map[string][]string)
	for k, v := range resp.Header {
		result.ResponseHeaders[k] = v
	}

	var reader io.Reader = resp.Body
	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "gzip":
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			result.ContentHashError = "Gzip reader error: " + err.Error()
		} else {
			defer gzReader.Close()
			reader = gzReader
		}
	case "deflate":
		zlibReader, err := zlib.NewReader(resp.Body)
		if err != nil {
			result.ContentHashError = "Deflate reader error: " + err.Error()
		} else {
			defer zlibReader.Close()
			reader = zlibReader
		}
	}

	var bodyBytes []byte
	limitedReader := io.LimitReader(reader, maxBodyReadBytes)
	rawBodyBytes, readErr := ioutil.ReadAll(limitedReader)

	if readErr != nil && readErr != io.EOF {
		if result.ContentHashError == "" {
			result.ContentHashError = "Read body error: " + readErr.Error()
		} else {
			result.ContentHashError += "; Read body error: " + readErr.Error()
		}
	} else {
		contentType := resp.Header.Get("Content-Type")
		utf8Reader, errConv := charset.NewReader(bytes.NewReader(rawBodyBytes), contentType)
		if errConv != nil {
			bodyBytes = rawBodyBytes
		} else {
			utf8Bytes, errReadUTF8 := ioutil.ReadAll(utf8Reader)
			if errReadUTF8 != nil {
				bodyBytes = rawBodyBytes
			} else {
				bodyBytes = utf8Bytes
			}
		}
		hash := sha256.Sum256(bodyBytes)
		result.ContentHash = fmt.Sprintf("%x", hash)
		result.ContentLength = len(bodyBytes)
		result.RawBody = rawBodyBytes // Store the read body bytes (could be truncated by limitedReader)
	}
	if clStr := resp.Header.Get("Content-Length"); clStr != "" {
		if cl, err := strconv.ParseInt(clStr, 10, 64); err == nil {
			result.ActualContentLength = cl
		}
	}

	result.AntiBotIndicators = make(map[string]string)
	if serverHeader, ok := resp.Header["Server"]; ok {
		for _, s := range serverHeader {
			lowerS := strings.ToLower(s)
			if strings.Contains(lowerS, "cloudflare") {
				result.AntiBotIndicators["Cloudflare_Server"] = s
			}
			if strings.Contains(lowerS, "akamaighost") {
				result.AntiBotIndicators["Akamai_Server"] = s
			}
		}
	}
	return result
}
