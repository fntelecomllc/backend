// File: backend/internal/api/handlers.go
// This file now primarily contains validation and server settings handlers.
// Other handlers have been moved to feature-specific files.
package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	// "io/ioutil" //ioutil is part of ForceCheckAllProxiesHandler, moved to proxy_handlers.go
	"log"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	// "os" // os is used by moved persona/proxy save functions
	// "path/filepath" // path/filepath is used by moved persona/proxy save functions
	// "sort" // sort is used by moved ListProxiesHandler
	"strings"
	"time"

	"github.com/fntelecomllc/domainflow/backend/internal/config"
	"github.com/fntelecomllc/domainflow/backend/internal/dnsvalidator"
	"github.com/fntelecomllc/domainflow/backend/internal/httpvalidator"
	// Keyword extractor no longer used directly in these validation handlers
	"github.com/fntelecomllc/domainflow/backend/internal/proxymanager"
	// "github.com/gorilla/mux" // mux is used by moved handlers for vars
	"golang.org/x/time/rate"
)

// Note: APIHandler, NewAPIHandler are in handler_base.go
// Note: campaignDNSSettingsStore, campaignStoreMutex are in handler_base.go
// Note: respondWithError, respondWithJSON, getProxyLogStr are in handler_utils.go
// Note: PingHandler is in ping_handler.go
// Note: Persona handlers are in persona_handlers.go
// Note: Proxy handlers are in proxy_handlers.go
// Note: Campaign handlers are in campaign_handlers.go
// Note: KeywordSet list handler is in keyword_set_handlers.go

// --- Structs for Validation Handlers ---

type DNSValidationRequest struct {
	Domains      []string `json:"domains"`
	DNSPersonaID *string  `json:"dnsPersonaId,omitempty"`
	CampaignID   *string  `json:"campaignId,omitempty"`
}

type DNSValidationResponse struct {
	Results []dnsvalidator.ValidationResult `json:"results"`
	Error   string                         `json:"error,omitempty"`
}

type HTTPValidationRequest struct {
    Domains       []string `json:"domains"`
    HTTPPersonaID *string  `json:"httpPersonaId,omitempty"`
    // KeywordSetID removed, keyword extraction is now a separate endpoint
}

type HTTPValidationResponse struct {
	Results []httpvalidator.ValidationResult `json:"results"`
	Error   string                          `json:"error,omitempty"`
}

// --- Helper Functions for Validation Handlers ---

func convertDNSPersonaConfig(jsonCfg config.DNSValidatorConfigJSON) config.DNSValidatorConfig {
    dnsStrategy := jsonCfg.ResolverStrategy
    if dnsStrategy == "" {
        dnsStrategy = "random_rotation"
    }
    validStrategies := map[string]bool{"random_rotation": true, "weighted_rotation": true, "sequential_failover": true}
    if !validStrategies[dnsStrategy] {
        log.Printf("Warning: Invalid DNS resolverStrategy '%s' in persona. Defaulting.", dnsStrategy)
        dnsStrategy = "random_rotation"
    }
    concurrentQueriesPerDomain := jsonCfg.ConcurrentQueriesPerDomain
    if concurrentQueriesPerDomain <= 0 {
        concurrentQueriesPerDomain = 1
    } else if concurrentQueriesPerDomain > 2 {
        concurrentQueriesPerDomain = 2
    }
    maxDnsGoroutines := jsonCfg.MaxConcurrentGoroutines
    if maxDnsGoroutines <= 0 {
        maxDnsGoroutines = 10
    }
    rateDPS := jsonCfg.RateLimitDPS
    if rateDPS <= 0 {
        rateDPS = config.DefaultRateLimitDPS
    }
    rateBurst := jsonCfg.RateLimitBurst
    if rateBurst <= 0 {
        rateBurst = config.DefaultRateLimitBurst
    }
    return config.DNSValidatorConfig{
        Resolvers:                  jsonCfg.Resolvers,
        UseSystemResolvers:         jsonCfg.UseSystemResolvers,
        QueryTimeout:               time.Duration(jsonCfg.QueryTimeoutSeconds) * time.Second,
        MaxDomainsPerRequest:       jsonCfg.MaxDomainsPerRequest,
        ResolverStrategy:           dnsStrategy,
        ResolversWeighted:          jsonCfg.ResolversWeighted,
        ResolversPreferredOrder:    jsonCfg.ResolversPreferredOrder,
        ConcurrentQueriesPerDomain: concurrentQueriesPerDomain,
        QueryDelayMin:              time.Duration(jsonCfg.QueryDelayMinMs) * time.Millisecond,
        QueryDelayMax:              time.Duration(jsonCfg.QueryDelayMaxMs) * time.Millisecond,
        MaxConcurrentGoroutines:    maxDnsGoroutines,
        RateLimitDPS:               rateDPS,
        RateLimitBurst:             rateBurst,
        QueryTimeoutSeconds:        jsonCfg.QueryTimeoutSeconds,
        JSONResolvers:              jsonCfg.Resolvers,
        JSONUseSystemResolvers:     jsonCfg.UseSystemResolvers,
        JSONMaxDomainsPerRequest:   jsonCfg.MaxDomainsPerRequest,
        JSONResolverStrategy:       dnsStrategy,
        JSONResolversWeighted:      jsonCfg.ResolversWeighted,
        JSONResolversPreferredOrder: jsonCfg.ResolversPreferredOrder,
        JSONConcurrentQueriesPerDomain: concurrentQueriesPerDomain,
        JSONQueryDelayMinMs:       jsonCfg.QueryDelayMinMs,
        JSONQueryDelayMaxMs:       jsonCfg.QueryDelayMaxMs,
        JSONMaxConcurrentGoroutines: maxDnsGoroutines,
        JSONRateLimitDPS:          rateDPS,
        JSONRateLimitBurst:        rateBurst,
    }
}

func (h *APIHandler) createHTTPClientForPersona(personaID *string) (*http.Client, string, map[string]string, int, *config.ProxyConfigEntry) {
    h.configMutex.RLock()
    serverDefaultHTTPCfg := h.Config.HTTPValidator
    allLoadedHTTPPersonas := h.Config.HTTPPersonas
    h.configMutex.RUnlock()

    var effectiveUserAgent string
    var effectiveHeaders map[string]string
    var effectiveMaxRedirects int = serverDefaultHTTPCfg.MaxRedirects
    var effectiveAllowInsecureTLS bool = serverDefaultHTTPCfg.AllowInsecureTLS
    var effectiveCookieMode string = "session"
    var effectiveTLSConfig *tls.Config
    var effectiveForceHTTP2 bool = true

    if personaID != nil && *personaID != "" {
        var chosenPersona *config.HTTPPersona
        for i := range allLoadedHTTPPersonas {
            if allLoadedHTTPPersonas[i].ID == *personaID {
                pCopy := allLoadedHTTPPersonas[i] // Make a copy to avoid pointer issues with loop variable
                chosenPersona = &pCopy
                break
            }
        }
        if chosenPersona != nil {
            log.Printf("API HTTP: Using Persona '%s'", *personaID)
            effectiveUserAgent = chosenPersona.UserAgent
            effectiveHeaders = chosenPersona.Headers
            if chosenPersona.CookieHandling.Mode != "" {
                effectiveCookieMode = chosenPersona.CookieHandling.Mode
            }
            
            // Begin TLS config part
            tlsCfg := &tls.Config{}
            tlsCfg.InsecureSkipVerify = effectiveAllowInsecureTLS // Already declared and set from serverDefaultHTTPCfg or persona

            if chosenPersona.TLSClientHello.MinVersion != "" {
                if v, ok := config.GetTLSVersion(chosenPersona.TLSClientHello.MinVersion); ok && v != 0 {
                    tlsCfg.MinVersion = v
                }
            }
            if chosenPersona.TLSClientHello.MaxVersion != "" {
                if v, ok := config.GetTLSVersion(chosenPersona.TLSClientHello.MaxVersion); ok && v != 0 {
                    tlsCfg.MaxVersion = v
                }
            }
            if len(chosenPersona.TLSClientHello.CipherSuites) > 0 {
                s, err := config.GetCipherSuites(chosenPersona.TLSClientHello.CipherSuites) // Use new err var
                if err == nil {
                    tlsCfg.CipherSuites = s
                } else {
                    log.Printf("Warn: Persona '%s' invalid ciphers: %v", *personaID, err)
                }
            }
            if len(chosenPersona.TLSClientHello.CurvePreferences) > 0 {
                c, err := config.GetCurvePreferences(chosenPersona.TLSClientHello.CurvePreferences) // Use new err var
                if err == nil {
                    tlsCfg.CurvePreferences = c
                } else {
                    log.Printf("Warn: Persona '%s' invalid curves: %v", *personaID, err)
                }
            }
            effectiveTLSConfig = tlsCfg // Assign to the broader scoped variable

            if chosenPersona.HTTP2Settings.Enabled != nil {
                effectiveForceHTTP2 = *chosenPersona.HTTP2Settings.Enabled
            }
            // End TLS config part
        } else {
            log.Printf("API HTTP: Persona ID '%s' not found. Using server defaults.", *personaID)
        }
    }

    // Apply server defaults if no persona or if persona didn't specify certain fields
    if effectiveUserAgent == "" {
        if len(serverDefaultHTTPCfg.UserAgents) > 0 {
            effectiveUserAgent = serverDefaultHTTPCfg.UserAgents[rand.Intn(len(serverDefaultHTTPCfg.UserAgents))]
        } else {
            effectiveUserAgent = "DomainFlowValidator/1.0 (DefaultUA)"
        }
        // Only apply default headers if persona didn't specify any, to allow persona to send no headers if desired.
        if effectiveHeaders == nil {
             effectiveHeaders = serverDefaultHTTPCfg.DefaultHeaders 
        }
        if effectiveTLSConfig == nil { // If not set by persona (e.g. persona had no TLSClientHello settings)
             effectiveTLSConfig = &tls.Config{InsecureSkipVerify: serverDefaultHTTPCfg.AllowInsecureTLS}
        }
    }
    // Ensure effectiveTLSConfig is not nil if it was not set by persona or defaults above
    // This path should ideally not be hit if logic is correct, but as a safeguard:
    if effectiveTLSConfig == nil {
        effectiveTLSConfig = &tls.Config{InsecureSkipVerify: serverDefaultHTTPCfg.AllowInsecureTLS}
    }


    var jar http.CookieJar
    if strings.ToLower(effectiveCookieMode) == "session" {
        var jarErr error
        jar, jarErr = cookiejar.New(nil)
        if jarErr != nil {
            log.Printf("Error creating cookie jar: %v", jarErr) 
        }
    }

    var selectedProxyEntry *config.ProxyConfigEntry
    var finalTransport *http.Transport

    if h.ProxyMgr != nil {
        proxyEntry, err := h.ProxyMgr.GetProxy()
        if err == nil && proxyEntry != nil {
            log.Printf("API HTTP: Attempting to use proxy ID '%s' (%s://%s)", proxyEntry.ID, proxyEntry.Protocol, proxyEntry.Address)
            // Temporarily pass nil for baseTransport, this whole function will be refactored/removed.
            proxyConfiguredTransport, errTransport := proxymanager.GetHTTPTransportForProxy(proxyEntry, nil)
            if errTransport == nil && proxyConfiguredTransport != nil {
                // Since baseTransport was nil, the proxyConfiguredTransport is new; apply TLS & HTTP2 settings.
                proxyConfiguredTransport.TLSClientConfig = effectiveTLSConfig 
                proxyConfiguredTransport.ForceAttemptHTTP2 = effectiveForceHTTP2
                finalTransport = proxyConfiguredTransport // Assign the proxy-configured transport
                selectedProxyEntry = proxyEntry
                log.Printf("API HTTP: Successfully configured transport with proxy ID '%s'", proxyEntry.ID)
            } else {
                log.Printf("API HTTP: Failed to get/configure transport for proxy ID '%s': %v. Falling back.", proxyEntry.ID, errTransport)
            }
        } else {
            log.Printf("API HTTP: No healthy proxy available from ProxyManager (%v). Using direct connection.", err)
        }
    }

    if finalTransport == nil {
        log.Printf("API HTTP: Using direct connection (no proxy or fallback).")
        finalTransport = &http.Transport{
            TLSClientConfig:       effectiveTLSConfig,
            Proxy:                 http.ProxyFromEnvironment,
            ForceAttemptHTTP2:     effectiveForceHTTP2,
            MaxIdleConns:          100,
            IdleConnTimeout:       90 * time.Second,
            TLSHandshakeTimeout:   10 * time.Second,
            ExpectContinueTimeout: 1 * time.Second,
            DisableKeepAlives:     false, 
        }
    }

    client := &http.Client{
        Jar:       jar,
        Transport: finalTransport,
        Timeout:   serverDefaultHTTPCfg.RequestTimeout, 
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= effectiveMaxRedirects {
                return http.ErrUseLastResponse
            }
            return nil
        },
    }
    return client, effectiveUserAgent, effectiveHeaders, effectiveMaxRedirects, selectedProxyEntry
}

func isProxyRelatedError(errStr string, proxyAddress string) bool {
    if errStr == "" {
        return false
    }
    lowerErr := strings.ToLower(errStr)
    if strings.Contains(lowerErr, "proxyconnect") || (proxyAddress != "" && strings.Contains(lowerErr, strings.ToLower(strings.Split(proxyAddress, ":")[0]))) || (proxyAddress != "" && strings.Contains(lowerErr, strings.ToLower(proxyAddress))) || strings.Contains(lowerErr, "http: proxy error") || strings.Contains(lowerErr, "socks connect") {
        return true
    }
    if strings.Contains(lowerErr, "connect: connection refused") {
        if proxyAddress != "" && strings.Contains(lowerErr, strings.ToLower(proxyAddress)) {
            return true
        }
    }
    if strings.Contains(lowerErr, "no such host") {
        if proxyAddress != "" && strings.Contains(lowerErr, strings.ToLower(strings.Split(proxyAddress, ":")[0])) {
            return true
        }
    }
    if proxyAddress != "" {
        if strings.Contains(lowerErr, "context deadline exceeded") || strings.Contains(lowerErr, "i/o timeout") || strings.Contains(lowerErr, "unexpected eof") || strings.Contains(lowerErr, "connection reset by peer") {
            return true
        }
    }
    return false
}

// --- DNS/HTTP Validation Handlers ---

func (h *APIHandler) DNSValidateHandler(w http.ResponseWriter, r *http.Request) {
    var req DNSValidationRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
        return
    }
    defer r.Body.Close()
    if len(req.Domains) == 0 {
        respondWithError(w, http.StatusBadRequest, "No domains provided")
        return
    }
    var effectiveDNSConfig config.DNSValidatorConfig
    var personaRateLimiter *rate.Limiter
    h.configMutex.RLock()
    if req.DNSPersonaID != nil && *req.DNSPersonaID != "" {
        var foundPersona *config.DNSPersona
        for _, p := range h.Config.DNSPersonas {
            if p.ID == *req.DNSPersonaID {
                fp := p
                foundPersona = &fp
                break
            }
        }
        if foundPersona != nil {
            effectiveDNSConfig = convertDNSPersonaConfig(foundPersona.Config)
            log.Printf("API DNS Batch: Using Persona '%s' for %d domains.", *req.DNSPersonaID, len(req.Domains))
        } else {
            log.Printf("API DNS Batch: Persona ID '%s' not found. Using server defaults.", *req.DNSPersonaID)
            effectiveDNSConfig = h.Config.DNSValidator
        }
    } else if req.CampaignID != nil && *req.CampaignID != "" {
        log.Printf("API DNS Batch: Campaign ID '%s' provided. Campaign logic TBD, using server defaults.", *req.CampaignID)
        effectiveDNSConfig = h.Config.DNSValidator
    } else {
        log.Printf("API DNS Batch: No Persona or Campaign ID. Using server defaults for %d domains.", len(req.Domains))
        effectiveDNSConfig = h.Config.DNSValidator
    }
    h.configMutex.RUnlock()
    if effectiveDNSConfig.MaxDomainsPerRequest > 0 && len(req.Domains) > effectiveDNSConfig.MaxDomainsPerRequest {
        respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Too many domains. Max %d for this configuration.", effectiveDNSConfig.MaxDomainsPerRequest))
        return
    }
    if effectiveDNSConfig.RateLimitDPS > 0 && effectiveDNSConfig.RateLimitBurst > 0 {
        personaRateLimiter = rate.NewLimiter(rate.Limit(effectiveDNSConfig.RateLimitDPS), effectiveDNSConfig.RateLimitBurst)
    }
    validator := dnsvalidator.New(effectiveDNSConfig)
    var results []dnsvalidator.ValidationResult
    if personaRateLimiter != nil {
        var allResults []dnsvalidator.ValidationResult
        for _, domainToValidate := range req.Domains {
            if err := personaRateLimiter.WaitN(r.Context(), 1); err != nil {
                log.Printf("API DNS Batch: Rate limiter context error for domain %s: %v", domainToValidate, err)
                allResults = append(allResults, dnsvalidator.ValidationResult{Domain: domainToValidate, Status: "Error", Error: "Rate limit error: " + err.Error(), Timestamp: time.Now().Format(time.RFC3339)})
                continue
            }
            singleDomainBatchResult := validator.ValidateDomains([]string{domainToValidate})
            allResults = append(allResults, singleDomainBatchResult...)
        }
        results = allResults
    } else {
        results = validator.ValidateDomains(req.Domains)
    }
    respondWithJSON(w, http.StatusOK, DNSValidationResponse{Results: results})
    log.Printf("API DNS Batch: Completed validation for %d domains.", len(req.Domains))
}

func (h *APIHandler) DNSValidateStreamHandler(w http.ResponseWriter, r *http.Request) {
    streamType := "DNS"
    flusher, ok := w.(http.Flusher)
    if !ok {
        log.Printf("API Error: %sValidateStreamHandler - Streaming unsupported.", streamType)
        respondWithError(w, http.StatusInternalServerError, "Streaming unsupported!")
        return
    }
    domainsQuery := r.URL.Query()["domain"]
    if len(domainsQuery) == 0 {
        log.Printf("API Error: %sValidateStreamHandler - No domains provided.", streamType)
        respondWithError(w, http.StatusBadRequest, "No domains provided")
        return
    }
    personaIDQuery := r.URL.Query().Get("dnsPersonaId")
    campaignIDQuery := r.URL.Query().Get("campaignId")
    var personaIDPtr *string
    if personaIDQuery != "" {
        personaIDPtr = &personaIDQuery
    }
    var campaignIDPtr *string
    if campaignIDQuery != "" {
        campaignIDPtr = &campaignIDQuery
    }
    h.configMutex.RLock()
    var effectiveDNSConfig config.DNSValidatorConfig = h.Config.DNSValidator
    var streamRateLimiter *rate.Limiter
    streamChunkSize := h.Config.Server.StreamChunkSize
    if streamChunkSize <= 0 {
        streamChunkSize = config.DefaultStreamChunkSize
    }
    if personaIDPtr != nil {
        var chosenPersona *config.DNSPersona
        for _, p := range h.Config.DNSPersonas {
            if p.ID == *personaIDPtr {
                pCopy := p
                chosenPersona = &pCopy
                break
            }
        }
        if chosenPersona != nil {
            effectiveDNSConfig = convertDNSPersonaConfig(chosenPersona.Config)
            log.Printf("API %s Stream: Using Persona '%s' (config for entire stream). Rate: %.2f DPS, %d Burst", streamType, *personaIDPtr, effectiveDNSConfig.RateLimitDPS, effectiveDNSConfig.RateLimitBurst)
        } else {
            log.Printf("API %s Stream: Persona ID '%s' not found. Using server defaults.", streamType, *personaIDPtr)
        }
    } else if campaignIDPtr != nil {
        log.Printf("API %s Stream: Campaign ID '%s' provided. Full campaign logic for stream persona TBD. Using server defaults.", streamType, *campaignIDPtr)
    } else {
        log.Printf("API %s Stream: No Persona/Campaign. Using server defaults.", streamType)
    }
    if streamRateLimiter == nil && effectiveDNSConfig.RateLimitDPS > 0 && effectiveDNSConfig.RateLimitBurst > 0 {
        streamRateLimiter = rate.NewLimiter(rate.Limit(effectiveDNSConfig.RateLimitDPS), effectiveDNSConfig.RateLimitBurst)
        log.Printf("API %s Stream: Initialized rate limiter: %.2f DPS, %d Burst", streamType, effectiveDNSConfig.RateLimitDPS, effectiveDNSConfig.RateLimitBurst)
    } else if streamRateLimiter == nil {
        log.Printf("API %s Stream: No rate limiting configured for this stream.", streamType)
    }
    h.configMutex.RUnlock()
    if effectiveDNSConfig.MaxDomainsPerRequest > 0 && len(domainsQuery) > effectiveDNSConfig.MaxDomainsPerRequest {
        log.Printf("API Error: %sValidateStreamHandler - Too many domains requested (%d) vs max allowed (%d).", streamType, len(domainsQuery), effectiveDNSConfig.MaxDomainsPerRequest)
        errorData := map[string]string{"error": fmt.Sprintf("Too many domains. Max %d for this configuration.", effectiveDNSConfig.MaxDomainsPerRequest)}
        jsonData, _ := json.Marshal(errorData)
        w.Header().Set("Content-Type", "text/event-stream")
        w.Header().Set("Cache-Control", "no-cache")
        w.Header().Set("Connection", "keep-alive")
        w.WriteHeader(http.StatusOK)
        fmt.Fprintf(w, "event: error\ndata: %s\n\n", string(jsonData))
        flusher.Flush()
        return
    }
    validator := dnsvalidator.New(effectiveDNSConfig)
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")
    w.Header().Set("Access-Control-Allow-Origin", "*")
    eventID := 0
    requestContext := r.Context()
    totalDomains := len(domainsQuery)
    log.Printf("API %s Stream: Starting to process %d domains in chunks of %d.", streamType, totalDomains, streamChunkSize)
    for i := 0; i < totalDomains; i += streamChunkSize {
        chunkEnd := i + streamChunkSize
        if chunkEnd > totalDomains {
            chunkEnd = totalDomains
        }
        currentChunk := domainsQuery[i:chunkEnd]
        log.Printf("API %s Stream: Processing chunk %d of %d (domains %d-%d of %d).", streamType, (i/streamChunkSize)+1, (totalDomains+streamChunkSize-1)/streamChunkSize, i+1, chunkEnd, totalDomains)
        for _, domain := range currentChunk {
            eventID++
            domainProcessingStart := time.Now()
            var result dnsvalidator.ValidationResult
            select {
            case <-requestContext.Done():
                log.Printf("API %s Stream: Client disconnected (chunk loop) for domain %s.", streamType, domain)
                fmt.Fprintf(w, "event: error\ndata: {\"message\": \"Client disconnected\"}\n\n")
                flusher.Flush()
                return
            default:
            }
            if streamRateLimiter != nil {
                log.Printf("API %s Stream: Domain '%s' (ID: %d) - Attempting token...", streamType, domain, eventID)
                waitStart := time.Now()
                if err := streamRateLimiter.Wait(requestContext); err != nil {
                    log.Printf("API %s Stream: Domain '%s' (ID: %d) - Rate limiter error after %s: %v", streamType, domain, eventID, time.Since(waitStart), err)
                    errorData := map[string]string{"domain": domain, "error": "Rate limit error: " + err.Error()}
                    jsonData, _ := json.Marshal(errorData)
                    fmt.Fprintf(w, "id: %d\nevent: dns_error\ndata: %s\n\n", eventID, string(jsonData))
                    flusher.Flush()
                    if err == context.Canceled || err == context.DeadlineExceeded {
                        return
                    }
                    continue
                }
                log.Printf("API %s Stream: Domain '%s' (ID: %d) - Token acquired after %s.", streamType, domain, eventID, time.Since(waitStart))
            }
            log.Printf("API %s Stream: Domain '%s' (ID: %d) - Starting validation.", streamType, domain, eventID)
            validationCallStart := time.Now()
            result = validator.ValidateSingleDomain(domain, requestContext)
            validationDuration := time.Since(validationCallStart)
            totalDomainProcessingTime := time.Since(domainProcessingStart)
            log.Printf("API %s Stream: Domain '%s' (ID: %d) - Validation took %s. Total domain processing: %s", streamType, domain, eventID, validationDuration, totalDomainProcessingTime)
            jsonData, err := json.Marshal(result)
            if err != nil {
                log.Printf("API Error: %sValidateStreamHandler - Marshal error for %s: %v", streamType, domain, err)
                errorData := map[string]string{"domain": domain, "error": "Marshal error: " + err.Error()}
                jsonErrData, _ := json.Marshal(errorData)
                fmt.Fprintf(w, "id: %d\nevent: dns_error\ndata: %s\n\n", eventID, string(jsonErrData))
                flusher.Flush()
                continue
            }
            fmt.Fprintf(w, "id: %d\nevent: dns_result\ndata: %s\n\n", eventID, string(jsonData))
            flusher.Flush()
        }
        log.Printf("API %s Stream: Finished processing chunk ending with domain index %d.", streamType, chunkEnd-1)
    }
    fmt.Fprintf(w, "event: done\ndata: %s Stream completed for %d domains.\n\n", streamType, totalDomains)
    flusher.Flush()
    log.Printf("API %s Stream: Completed all chunks for %d domains.", streamType, totalDomains)
}

func (h *APIHandler) HTTPValidateHandler(w http.ResponseWriter, r *http.Request) {
    var req HTTPValidationRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
        return
    }
    defer r.Body.Close()
    if len(req.Domains) == 0 {
        respondWithError(w, http.StatusBadRequest, "No domains provided")
        return
    }

    h.configMutex.RLock()
    serverDefaultHTTPConfig := h.Config.HTTPValidator
    h.configMutex.RUnlock()

    // KeywordSetID and related logic removed.

    if serverDefaultHTTPConfig.MaxDomainsPerRequest > 0 && len(req.Domains) > serverDefaultHTTPConfig.MaxDomainsPerRequest {
        respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Too many domains. Max %d", serverDefaultHTTPConfig.MaxDomainsPerRequest))
        return
    }

    clientToUse, ua, headers, _, usedProxyForBatch := h.createHTTPClientForPersona(req.HTTPPersonaID)
    batchTimeout := serverDefaultHTTPConfig.RequestTimeout * time.Duration(len(req.Domains))
    if len(req.Domains) > 1 {
        batchTimeout += 5 * time.Second 
    } else {
        batchTimeout += 2 * time.Second 
    }
    batchCtx, batchCancel := context.WithTimeout(r.Context(), batchTimeout)
    defer batchCancel()

    log.Printf("API HTTP Batch: Validating %d domains. User-Agent: '%s'. Proxy: %s.", len(req.Domains), ua, getProxyLogStr(usedProxyForBatch))

    httpVal := httpvalidator.New(serverDefaultHTTPConfig)
    results := httpVal.ValidateDomainsWithClient(req.Domains, clientToUse, ua, headers, batchCtx)
    
    // Keyword extraction logic removed.

    if usedProxyForBatch != nil && h.ProxyMgr != nil {
        batchOverallProxyCallSuccess := true
        var firstProxyRelatedErrorEncountered error
        for _, res := range results {
            if isProxyRelatedError(res.Error, usedProxyForBatch.Address) {
                batchOverallProxyCallSuccess = false
                firstProxyRelatedErrorEncountered = errors.New(res.Error)
                log.Printf("API HTTP Batch: Proxy ID '%s' encountered a proxy-related error for domain '%s': %s", usedProxyForBatch.ID, res.Domain, res.Error)
                break
            }
        }
        h.ProxyMgr.ReportProxyHealth(usedProxyForBatch.ID, batchOverallProxyCallSuccess, firstProxyRelatedErrorEncountered)
    }

    respondWithJSON(w, http.StatusOK, HTTPValidationResponse{Results: results})
}


func (h *APIHandler) HTTPValidateStreamHandler(w http.ResponseWriter, r *http.Request) {
    streamType := "HTTP"
    flusher, ok := w.(http.Flusher)
    if !ok {
        log.Printf("API Error: %sValidateStreamHandler - Streaming unsupported.", streamType)
        respondWithError(w, http.StatusInternalServerError, "Streaming unsupported!")
        return
    }

    domainsQuery := r.URL.Query()["domain"]
    if len(domainsQuery) == 0 {
        log.Printf("API Error: %sValidateStreamHandler - No domains provided.", streamType)
        respondWithError(w, http.StatusBadRequest, "No domains provided")
        return
    }

    personaIDQuery := r.URL.Query().Get("httpPersonaId")
    // keywordSetIDQuery := r.URL.Query().Get("keywordSetId") // Removed

    var personaIDPtr *string
    if personaIDQuery != "" {
        personaIDPtr = &personaIDQuery
    }

    h.configMutex.RLock()
    serverDefaultHTTPConfig := h.Config.HTTPValidator
    // selectedKeywordSet lookup removed.
    
    var streamRateLimiter *rate.Limiter
    streamChunkSize := h.Config.Server.StreamChunkSize
    if streamChunkSize <= 0 {
        streamChunkSize = config.DefaultStreamChunkSize
    }

    if personaIDPtr != nil {
        var chosenPersona *config.HTTPPersona
        for _, p := range h.Config.HTTPPersonas {
            if p.ID == *personaIDPtr {
                pCopy := p 
                chosenPersona = &pCopy
                break
            }
        }
        if chosenPersona != nil {
            log.Printf("API %s Stream: Using Persona '%s' settings for client creation per chunk.", streamType, *personaIDPtr)
            if chosenPersona.RateLimitDPS > 0 && chosenPersona.RateLimitBurst > 0 {
                streamRateLimiter = rate.NewLimiter(rate.Limit(chosenPersona.RateLimitDPS), chosenPersona.RateLimitBurst)
                log.Printf("API %s Stream: Persona '%s' rate limits applied: DPS=%.2f, Burst=%d", streamType, *personaIDPtr, chosenPersona.RateLimitDPS, chosenPersona.RateLimitBurst)
            } else {
                log.Printf("API %s Stream: Persona '%s' has no specific rate limits, server defaults for rate limiting will apply if configured.", streamType, *personaIDPtr)
            }
        } else {
            log.Printf("API %s Stream: Persona ID '%s' not found. Using server defaults for client and rate limiting.", streamType, *personaIDPtr)
        }
    } else {
        log.Printf("API %s Stream: No Persona ID. Using server defaults for client and rate limiting.", streamType)
    }

    if streamRateLimiter == nil && serverDefaultHTTPConfig.RateLimitDPS > 0 && serverDefaultHTTPConfig.RateLimitBurst > 0 {
        streamRateLimiter = rate.NewLimiter(rate.Limit(serverDefaultHTTPConfig.RateLimitDPS), serverDefaultHTTPConfig.RateLimitBurst)
        log.Printf("API %s Stream: Using server default HTTP rate limits: DPS=%.2f, Burst=%d", streamType, serverDefaultHTTPConfig.RateLimitDPS, serverDefaultHTTPConfig.RateLimitBurst)
    } else if streamRateLimiter == nil {
        log.Printf("API %s Stream: No rate limiting configured for this stream.", streamType)
    }
    h.configMutex.RUnlock()

    if serverDefaultHTTPConfig.MaxDomainsPerRequest > 0 && len(domainsQuery) > serverDefaultHTTPConfig.MaxDomainsPerRequest {
        log.Printf("API Error: %sValidateStreamHandler - Too many domains requested (%d) vs max allowed (%d).", streamType, len(domainsQuery), serverDefaultHTTPConfig.MaxDomainsPerRequest)
        errorData := map[string]string{"error": fmt.Sprintf("Too many domains. Max %d for this configuration.", serverDefaultHTTPConfig.MaxDomainsPerRequest)}
        jsonData, _ := json.Marshal(errorData)
        w.Header().Set("Content-Type", "text/event-stream")
        w.Header().Set("Cache-Control", "no-cache")
        w.Header().Set("Connection", "keep-alive")
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.WriteHeader(http.StatusOK)
        fmt.Fprintf(w, "event: error\ndata: %s\n\n", string(jsonData))
        flusher.Flush()
        return
    }

    httpVal := httpvalidator.New(serverDefaultHTTPConfig)

    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")
    w.Header().Set("Access-Control-Allow-Origin", "*")

    eventID := 0
    requestContext := r.Context()
    totalDomains := len(domainsQuery)
    
    log.Printf("API %s Stream: Starting to process %d domains in chunks of %d.", streamType, totalDomains, streamChunkSize)

    for i := 0; i < totalDomains; i += streamChunkSize {
        chunkEnd := i + streamChunkSize
        if chunkEnd > totalDomains {
            chunkEnd = totalDomains
        }
        currentChunk := domainsQuery[i:chunkEnd]
        httpClient, userAgent, headers, _, usedProxyForChunk := h.createHTTPClientForPersona(personaIDPtr)
        log.Printf("API %s Stream: Processing chunk %d of %d (domains %d-%d of %d). Client UA: '%s'. Proxy: %s", streamType, (i/streamChunkSize)+1, (totalDomains+streamChunkSize-1)/streamChunkSize, i+1, chunkEnd, totalDomains, userAgent, getProxyLogStr(usedProxyForChunk))

        for _, domain := range currentChunk {
            eventID++
            domainProcessingStart := time.Now()
            var result httpvalidator.ValidationResult 

            select {
            case <-requestContext.Done():
                log.Printf("API %s Stream: Client disconnected (chunk loop) for domain %s.", streamType, domain)
                fmt.Fprintf(w, "event: error\ndata: {\"message\": \"Client disconnected\"}\n\n")
                flusher.Flush()
                return
            default:
            }

            if streamRateLimiter != nil {
                log.Printf("API %s Stream: Domain '%s' (ID: %d) - Attempting token...", streamType, domain, eventID)
                waitStart := time.Now()
                if err := streamRateLimiter.Wait(requestContext); err != nil {
                    log.Printf("API %s Stream: Domain '%s' (ID: %d) - Rate limiter error after %s: %v", streamType, domain, eventID, time.Since(waitStart), err)
                    errorData := map[string]string{"domain": domain, "error": "Rate limit error: " + err.Error()}
                    jsonData, _ := json.Marshal(errorData)
                    fmt.Fprintf(w, "id: %d\nevent: http_error\ndata: %s\n\n", eventID, string(jsonData))
                    flusher.Flush()
                    if err == context.Canceled || err == context.DeadlineExceeded {
                        return
                    }
                    continue
                }
                log.Printf("API %s Stream: Domain '%s' (ID: %d) - Token acquired after %s.", streamType, domain, eventID, time.Since(waitStart))
            }

            log.Printf("API %s Stream: Domain '%s' (ID: %d) - Starting validation.", streamType, domain, eventID)
            validationCallStart := time.Now()
            result = httpVal.ValidateSingleDomainWithClient(domain, httpClient, userAgent, headers, requestContext)
            validationDuration := time.Since(validationCallStart)
            
            // Keyword Extraction for stream REMOVED
            
            totalDomainProcessingTime := time.Since(domainProcessingStart)
            log.Printf("API %s Stream: Domain '%s' (ID: %d) - Validation took %s. Total processing: %s", streamType, domain, eventID, validationDuration, totalDomainProcessingTime)

            if usedProxyForChunk != nil && h.ProxyMgr != nil {
                isActualProxyFailure := isProxyRelatedError(result.Error, usedProxyForChunk.Address)
                proxyCallConsideredSuccessful := !isActualProxyFailure
                var errorForReportingToProxyMgr error
                if isActualProxyFailure {
                    errorForReportingToProxyMgr = errors.New(result.Error)
                }
                h.ProxyMgr.ReportProxyHealth(usedProxyForChunk.ID, proxyCallConsideredSuccessful, errorForReportingToProxyMgr)
            }

            jsonData, err := json.Marshal(result) 
            if err != nil {
                log.Printf("API Error: %sValidateStreamHandler - Marshal error for %s: %v", streamType, domain, err)
                errorData := map[string]string{"domain": domain, "error": "Marshal error: " + err.Error()}
                jsonErrData, _ := json.Marshal(errorData)
                fmt.Fprintf(w, "id: %d\nevent: http_error\ndata: %s\n\n", eventID, string(jsonErrData))
                flusher.Flush()
                continue
            }
            fmt.Fprintf(w, "id: %d\nevent: http_result\ndata: %s\n\n", eventID, string(jsonData))
            flusher.Flush()
        }
        log.Printf("API %s Stream: Finished processing chunk ending with domain index %d.", streamType, chunkEnd-1)
    }
    fmt.Fprintf(w, "event: done\ndata: %s Stream completed for %d domains.\n\n", streamType, totalDomains)
    flusher.Flush()
    log.Printf("API %s Stream: Completed all chunks for %d domains.", streamType, totalDomains)
}

// Note: Server Settings Handlers (GetServerConfigHandler, UpdateServerConfigHandler, GetDNSConfigHandler, UpdateDNSConfigHandler, 
// GetHTTPConfigHandler, UpdateHTTPConfigHandler, GetLoggingConfigHandler, UpdateLoggingConfigHandler)
// have been moved to server_settings_handlers.go

// Note: Utility functions (respondWithError, respondWithJSON, getProxyLogStr) are in handler_utils.go
// Note: KeywordSet list items/handlers are in keyword_set_handlers.go
