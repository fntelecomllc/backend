// File: backend/internal/proxymanager/proxymanager.go
package proxymanager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fntelecomllc/domainflow/backend/internal/config"
)

// Constants, ProxyTestResult, TestProxy, ProxyStatus, ProxyManager struct, NewProxyManager, 
// performSingleProxyCheck, updateActiveProxies, GetProxy, ReportProxyHealth, 
// GetHTTPTransportForProxy, GetAllProxyStatuses, ForceCheckSingleProxy, ForceCheckProxiesAsync
// ... (These remain IDENTICAL to the last complete version you have) ...
const ( ProxyTestTimeout = 10 * time.Second; ProxyTestURL = "https://httpbin.org/ip"; DefaultInitialHealthCheckTimeout = 7 * time.Second; MaxConcurrentInitialChecks = 10 )
type ProxyTestResult struct { ProxyID string `json:"proxyId"`; Success bool `json:"success"`; StatusCode int `json:"statusCode,omitempty"`; ReturnedIP string `json:"returnedIp,omitempty"`; Error string `json:"error,omitempty"`; DurationMs int64 `json:"durationMs"`}
func TestProxy(proxyEntry config.ProxyConfigEntry) ProxyTestResult { startTime := time.Now(); result := ProxyTestResult{ProxyID: proxyEntry.ID}; lcProtocol := strings.ToLower(proxyEntry.Protocol); if lcProtocol != "http" && lcProtocol != "https" { result.Error = fmt.Sprintf("Unsupported proxy protocol for testing: %s. Only http/https are supported.", proxyEntry.Protocol); result.DurationMs = time.Since(startTime).Milliseconds(); return result }; proxyURLString := fmt.Sprintf("%s://%s", proxyEntry.Protocol, proxyEntry.Address); if proxyEntry.Username != "" { proxyURLString = fmt.Sprintf("%s://%s:%s@%s", proxyEntry.Protocol, url.QueryEscape(proxyEntry.Username), url.QueryEscape(proxyEntry.Password), proxyEntry.Address) }; proxyURL, err := url.Parse(proxyURLString); if err != nil { result.Error = "Failed to parse proxy URL: " + err.Error(); result.DurationMs = time.Since(startTime).Milliseconds(); return result }; transport := &http.Transport{ Proxy: http.ProxyURL(proxyURL), TLSHandshakeTimeout: ProxyTestTimeout / 2, }; client := &http.Client{ Transport: transport, Timeout:   ProxyTestTimeout, }; ctx, cancel := context.WithTimeout(context.Background(), ProxyTestTimeout); defer cancel(); req, err := http.NewRequestWithContext(ctx, "GET", ProxyTestURL, nil); if err != nil { result.Error = "Failed to create test request: " + err.Error(); result.DurationMs = time.Since(startTime).Milliseconds(); return result }; req.Header.Set("User-Agent", "DomainFlowProxyTester/1.0"); resp, err := client.Do(req); if err != nil { result.Error = "Proxy test request failed: " + err.Error(); if urlErr, ok := err.(*url.Error); ok && urlErr.Timeout() { result.Error = "Proxy test request timed out: " + err.Error() } else if ctx.Err() == context.DeadlineExceeded { result.Error = "Proxy test request context deadline exceeded (timeout)." }; result.DurationMs = time.Since(startTime).Milliseconds(); return result }; defer resp.Body.Close(); result.StatusCode = resp.StatusCode; body, err := ioutil.ReadAll(resp.Body); if err != nil { result.Error = "Failed to read proxy test response body: " + err.Error(); result.DurationMs = time.Since(startTime).Milliseconds(); return result }; if resp.StatusCode == http.StatusOK { var ipResponse struct { Origin string `json:"origin"` }; if err := json.Unmarshal(body, &ipResponse); err == nil { result.ReturnedIP = ipResponse.Origin; result.Success = true } else { result.Error = "Failed to parse IP from proxy test response: " + err.Error() + " Body: " + string(body) } } else { result.Error = fmt.Sprintf("Proxy test request returned status %d. Body: %s", resp.StatusCode, string(body)) }; result.DurationMs = time.Since(startTime).Milliseconds(); return result }
type ProxyStatus struct { config.ProxyConfigEntry; IsHealthy bool `json:"isHealthy"`; LastFailure time.Time `json:"lastFailure,omitempty"`; ConsecutiveFailures int `json:"consecutiveFailures"`}
type ProxyManager struct { allProxies []*ProxyStatus; activeProxies []*ProxyStatus; mu sync.RWMutex; currentIndex int; healthCheckTimeout time.Duration }
func NewProxyManager(entries []config.ProxyConfigEntry, initialCheckTimeout time.Duration) *ProxyManager { pm := &ProxyManager{ allProxies: make([]*ProxyStatus, 0, len(entries)), activeProxies: make([]*ProxyStatus, 0, len(entries)), currentIndex: 0, healthCheckTimeout: initialCheckTimeout, }; if pm.healthCheckTimeout <= 0 { pm.healthCheckTimeout = DefaultInitialHealthCheckTimeout }; log.Printf("ProxyManager: Initializing with %d proxy entries.", len(entries)); var supportedProxies []*ProxyStatus; for _, entry := range entries { lcProtocol := strings.ToLower(entry.Protocol); if lcProtocol != "http" && lcProtocol != "https" { log.Printf("ProxyManager: Skipping unsupported proxy protocol '%s' for proxy ID '%s' (%s)", entry.Protocol, entry.ID, entry.Address); continue }; ps := &ProxyStatus{ ProxyConfigEntry: entry, IsHealthy: false, }; supportedProxies = append(supportedProxies, ps) }; pm.allProxies = supportedProxies; log.Printf("ProxyManager: Performing initial health checks for %d supported proxies (timeout per proxy: %s)...", len(pm.allProxies), pm.healthCheckTimeout); var wg sync.WaitGroup; semaphore := make(chan struct{}, MaxConcurrentInitialChecks); for _, ps := range pm.allProxies { wg.Add(1); semaphore <- struct{}{}; go func(proxyStatus *ProxyStatus) { defer wg.Done(); defer func() { <-semaphore }(); ctx, cancel := context.WithTimeout(context.Background(), pm.healthCheckTimeout); defer cancel(); checkResult := performSingleProxyCheck(ctx, proxyStatus.ProxyConfigEntry); pm.mu.Lock(); if checkResult.Success { proxyStatus.IsHealthy = true; proxyStatus.LastFailure = time.Time{}; proxyStatus.ConsecutiveFailures = 0; log.Printf("ProxyManager: Initial health check PASSED for proxy ID '%s' (%s)", proxyStatus.ID, proxyStatus.Address) } else { proxyStatus.IsHealthy = false; proxyStatus.LastFailure = time.Now(); log.Printf("ProxyManager: Initial health check FAILED for proxy ID '%s' (%s): %s", proxyStatus.ID, proxyStatus.Address, checkResult.Error) }; pm.mu.Unlock() }(ps) }; wg.Wait(); pm.mu.Lock(); pm.updateActiveProxies(); pm.mu.Unlock(); log.Printf("ProxyManager: Initialization and initial health checks complete. Total managed: %d, Initially active: %d", len(pm.allProxies), len(pm.activeProxies)); return pm }
func performSingleProxyCheck(ctx context.Context, proxyEntry config.ProxyConfigEntry) ProxyTestResult { result := ProxyTestResult{ProxyID: proxyEntry.ID, Success: false}; proxyURLString := fmt.Sprintf("%s://%s", proxyEntry.Protocol, proxyEntry.Address); if proxyEntry.Username != "" { proxyURLString = fmt.Sprintf("%s://%s:%s@%s", proxyEntry.Protocol, url.QueryEscape(proxyEntry.Username), url.QueryEscape(proxyEntry.Password), proxyEntry.Address) }; proxyURL, err := url.Parse(proxyURLString); if err != nil { result.Error = "failed to parse proxy URL: " + err.Error(); return result }; transport := &http.Transport{ Proxy: http.ProxyURL(proxyURL), TLSHandshakeTimeout: DefaultInitialHealthCheckTimeout / 2, DisableKeepAlives: true, }; client := &http.Client{ Transport: transport, Timeout: DefaultInitialHealthCheckTimeout + (2 * time.Second),}; req, err := http.NewRequestWithContext(ctx, "GET", ProxyTestURL, nil); if err != nil { result.Error = "failed to create health check request: " + err.Error(); return result }; req.Header.Set("User-Agent", "DomainFlowInitialProxyHealthCheck/1.0"); resp, err := client.Do(req); if err != nil { if ctx.Err() == context.Canceled { result.Error = "health check canceled by parent context" } else if ctx.Err() == context.DeadlineExceeded { result.Error = "health check timed out (context deadline)" } else if urlErr, ok := err.(*url.Error); ok && urlErr.Timeout() { result.Error = "health check timed out (url.Error)" } else { result.Error = "health check request failed: " + err.Error() }; return result }; defer resp.Body.Close(); if resp.StatusCode >= 200 && resp.StatusCode < 300 { _, copyErr := ioutil.ReadAll(io.LimitReader(resp.Body, 512)); if copyErr != nil { result.Error = "failed to read small part of health check response body: " + copyErr.Error(); return result }; result.Success = true } else { result.Error = fmt.Sprintf("health check request returned status %d", resp.StatusCode) }; return result }
func (pm *ProxyManager) updateActiveProxies() { previousActiveCount := len(pm.activeProxies); pm.activeProxies = make([]*ProxyStatus, 0, len(pm.allProxies)); for _, p := range pm.allProxies { isUserEnabled := true; if p.UserEnabled != nil { isUserEnabled = *p.UserEnabled }; if p.IsHealthy && isUserEnabled { pm.activeProxies = append(pm.activeProxies, p) } }; if len(pm.activeProxies) > 0 && pm.currentIndex >= len(pm.activeProxies) { pm.currentIndex = 0 } else if len(pm.activeProxies) == 0 { pm.currentIndex = 0 }; if len(pm.activeProxies) != previousActiveCount { log.Printf("ProxyManager: Active proxies updated. Count changed from %d to %d.", previousActiveCount, len(pm.activeProxies)) } }
func (pm *ProxyManager) GetProxy() (*config.ProxyConfigEntry, error) { pm.mu.Lock(); defer pm.mu.Unlock(); if len(pm.activeProxies) == 0 { log.Println("ProxyManager: GetProxy - No healthy and enabled proxies available."); return nil, fmt.Errorf("no healthy and enabled proxies available") }; if pm.currentIndex >= len(pm.activeProxies) { pm.currentIndex = 0 }; proxyStatus := pm.activeProxies[pm.currentIndex]; pm.currentIndex = (pm.currentIndex + 1) % len(pm.activeProxies); proxyConfCopy := proxyStatus.ProxyConfigEntry; log.Printf("ProxyManager: Dispensing proxy ID '%s' (%s://%s)", proxyConfCopy.ID, proxyConfCopy.Protocol, proxyConfCopy.Address); return &proxyConfCopy, nil }
func (pm *ProxyManager) ReportProxyHealth(proxyID string, wasSuccessful bool, failureError error) { pm.mu.Lock(); defer pm.mu.Unlock(); var foundProxy *ProxyStatus; var foundIndex = -1; for i, ps := range pm.allProxies { if ps.ID == proxyID { foundProxy = ps; foundIndex = i; break } }; if foundProxy == nil { log.Printf("ProxyManager: ReportProxyHealth called for unknown proxy ID '%s'", proxyID); return }; log.Printf("ProxyManager: Health report for Proxy ID '%s' (%s). Successful: %t. Error: %v", proxyID, foundProxy.Address, wasSuccessful, failureError); statusChanged := false; if wasSuccessful { if !foundProxy.IsHealthy { log.Printf("ProxyManager: Proxy ID '%s' (%s) is now marked HEALTHY after successful use.", proxyID, foundProxy.Address); statusChanged = true }; foundProxy.IsHealthy = true; foundProxy.ConsecutiveFailures = 0 } else { if foundProxy.IsHealthy { log.Printf("ProxyManager: Proxy ID '%s' (%s) reported as FAILED. Error: %v. Marking as UNHEALTHY.", proxyID, foundProxy.Address, failureError); statusChanged = true } else { log.Printf("ProxyManager: Proxy ID '%s' (%s) reported as FAILED again. Error: %v. Consecutive failures: %d", proxyID, foundProxy.Address, failureError, foundProxy.ConsecutiveFailures+1) }; foundProxy.IsHealthy = false; foundProxy.LastFailure = time.Now(); foundProxy.ConsecutiveFailures++ }; if statusChanged { pm.allProxies[foundIndex] = foundProxy; pm.updateActiveProxies() } else if foundIndex != -1 { pm.allProxies[foundIndex] = foundProxy } }

// GetHTTPTransportForProxy configures the provided baseTransport to use the specified proxy.
// If baseTransport is nil, it creates a new default transport.
func GetHTTPTransportForProxy(pEntry *config.ProxyConfigEntry, baseTransport *http.Transport) (*http.Transport, error) {
	if pEntry == nil || pEntry.Address == "" {
		return nil, fmt.Errorf("GetHTTPTransportForProxy: proxy entry is nil or address is empty")
	}
	lcProtocol := strings.ToLower(pEntry.Protocol)
	if lcProtocol != "http" && lcProtocol != "https" { // Add SOCKS5 later if needed
		return nil, fmt.Errorf("GetHTTPTransportForProxy: unsupported proxy protocol '%s' for proxy ID '%s'. Only http/https supported", pEntry.Protocol, pEntry.ID)
	}

	proxyURLString := fmt.Sprintf("%s://%s", pEntry.Protocol, pEntry.Address)
	if pEntry.Username != "" {
		proxyURLString = fmt.Sprintf("%s://%s:%s@%s", pEntry.Protocol, url.QueryEscape(pEntry.Username), url.QueryEscape(pEntry.Password), pEntry.Address)
	}

	proxyURL, err := url.Parse(proxyURLString)
	if err != nil {
		return nil, fmt.Errorf("GetHTTPTransportForProxy: failed to parse proxy URL '%s': %w", proxyURLString, err)
	}

	var transportToUse *http.Transport
	if baseTransport != nil {
		transportToUse = baseTransport.Clone()
	} else {
		transportToUse = &http.Transport{
			DialContext:           nil, 
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConnsPerHost:   10,
		}
	}
	
	transportToUse.Proxy = http.ProxyURL(proxyURL)
	// TLSClientConfig should be inherited from baseTransport via Clone(), or set by caller before this.

	return transportToUse, nil
}

func (pm *ProxyManager) GetAllProxyStatuses() []ProxyStatus { pm.mu.RLock(); defer pm.mu.RUnlock(); statuses := make([]ProxyStatus, len(pm.allProxies)); for i, ps := range pm.allProxies { statuses[i] = *ps }; return statuses }
func (pm *ProxyManager) ForceCheckSingleProxy(proxyID string) (*ProxyStatus, error) { pm.mu.Lock(); defer pm.mu.Unlock(); var targetProxyStatus *ProxyStatus; var targetIndex = -1; for i, ps := range pm.allProxies { if ps.ID == proxyID { targetProxyStatus = ps; targetIndex = i; break } }; if targetProxyStatus == nil { log.Printf("ProxyManager: ForceCheckSingleProxy - Proxy ID '%s' not found.", proxyID); return nil, fmt.Errorf("proxy ID '%s' not found", proxyID) }; log.Printf("ProxyManager: ForceCheckSingleProxy - Manually checking health for proxy ID '%s' (%s)...", targetProxyStatus.ID, targetProxyStatus.Address); ctx, cancel := context.WithTimeout(context.Background(), pm.healthCheckTimeout); defer cancel(); checkResult := performSingleProxyCheck(ctx, targetProxyStatus.ProxyConfigEntry); statusChanged := false; if checkResult.Success { if !targetProxyStatus.IsHealthy { statusChanged = true; log.Printf("ProxyManager: ForceCheckSingleProxy - Proxy ID '%s' (%s) PASSED manual check and is now HEALTHY.", targetProxyStatus.ID, targetProxyStatus.Address) }; targetProxyStatus.IsHealthy = true; targetProxyStatus.LastFailure = time.Time{}; targetProxyStatus.ConsecutiveFailures = 0 } else { if targetProxyStatus.IsHealthy { statusChanged = true; log.Printf("ProxyManager: ForceCheckSingleProxy - Proxy ID '%s' (%s) FAILED manual check: %s. Marking UNHEALTHY.", targetProxyStatus.ID, targetProxyStatus.Address, checkResult.Error) } else { log.Printf("ProxyManager: ForceCheckSingleProxy - Proxy ID '%s' (%s) FAILED manual check again: %s.", targetProxyStatus.ID, targetProxyStatus.Address, checkResult.Error) }; targetProxyStatus.IsHealthy = false; targetProxyStatus.LastFailure = time.Now(); if checkResult.Success { targetProxyStatus.ConsecutiveFailures = 0 } else if targetProxyStatus.ConsecutiveFailures == 0 { targetProxyStatus.ConsecutiveFailures = 1 } }; pm.allProxies[targetIndex] = targetProxyStatus; if statusChanged { pm.updateActiveProxies() }; statusCopy := *targetProxyStatus; return &statusCopy, nil }
func (pm *ProxyManager) ForceCheckProxiesAsync(idsToCheck []string) { log.Printf("ProxyManager: ForceCheckProxiesAsync received request for %d IDs (or all if empty).", len(idsToCheck)); go func() { pm.mu.RLock(); proxiesToActuallyCheck := make([]*ProxyStatus, 0); if len(idsToCheck) == 0 { log.Printf("ProxyManager: ForceCheckProxiesAsync - Checking all %d managed proxies.", len(pm.allProxies)); for _, p := range pm.allProxies { proxiesToActuallyCheck = append(proxiesToActuallyCheck, p) } } else { idMap := make(map[string]bool); for _, id := range idsToCheck { idMap[id] = true }; for _, ps := range pm.allProxies { if idMap[ps.ID] { proxiesToActuallyCheck = append(proxiesToActuallyCheck, ps) } }; log.Printf("ProxyManager: ForceCheckProxiesAsync - Checking %d specified proxies.", len(proxiesToActuallyCheck)) }; pm.mu.RUnlock(); if len(proxiesToActuallyCheck) == 0 { log.Printf("ProxyManager: ForceCheckProxiesAsync - No proxies found to check."); return }; var wgChecks sync.WaitGroup; semaphore := make(chan struct{}, MaxConcurrentInitialChecks); var overallStatusChangedSinceStartOfAsyncOp bool; for _, ps := range proxiesToActuallyCheck { wgChecks.Add(1); semaphore <- struct{}{}; go func(proxyStatus *ProxyStatus) { defer wgChecks.Done(); defer func() { <-semaphore }(); ctx, cancel := context.WithTimeout(context.Background(), pm.healthCheckTimeout); defer cancel(); healthBeforeThisCheck := proxyStatus.IsHealthy; checkResult := performSingleProxyCheck(ctx, proxyStatus.ProxyConfigEntry); pm.mu.Lock(); if checkResult.Success { proxyStatus.IsHealthy = true; proxyStatus.LastFailure = time.Time{}; proxyStatus.ConsecutiveFailures = 0; if !healthBeforeThisCheck { overallStatusChangedSinceStartOfAsyncOp = true; log.Printf("ProxyManager: ForceCheckProxiesAsync - Proxy ID '%s' (%s) PASSED check and is now HEALTHY.", proxyStatus.ID, proxyStatus.Address) } } else { proxyStatus.IsHealthy = false; proxyStatus.LastFailure = time.Now(); if healthBeforeThisCheck { overallStatusChangedSinceStartOfAsyncOp = true; log.Printf("ProxyManager: ForceCheckProxiesAsync - Proxy ID '%s' (%s) FAILED check: %s. Marking UNHEALTHY.", proxyStatus.ID, proxyStatus.Address, checkResult.Error); proxyStatus.ConsecutiveFailures = 1 } else { log.Printf("ProxyManager: ForceCheckProxiesAsync - Proxy ID '%s' (%s) FAILED check again: %s.", proxyStatus.ID, proxyStatus.Address, checkResult.Error); if proxyStatus.ConsecutiveFailures == 0 { proxyStatus.ConsecutiveFailures = 1 } } }; pm.mu.Unlock() }(ps) }; wgChecks.Wait(); if overallStatusChangedSinceStartOfAsyncOp { pm.mu.Lock(); pm.updateActiveProxies(); pm.mu.Unlock(); log.Printf("ProxyManager: ForceCheckProxiesAsync - Finished. Active proxy list updated due to health status changes.") } else { log.Printf("ProxyManager: ForceCheckProxiesAsync - Finished. No health statuses changed that required active list update.") } }() }

// UpdateProxyUserEnabledStatus updates the UserEnabled flag for a specific proxy
// and rebuilds the active proxy list.
func (pm *ProxyManager) UpdateProxyUserEnabledStatus(proxyID string, isEnabled bool) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var foundProxy *ProxyStatus
	for _, ps := range pm.allProxies {
		if ps.ID == proxyID {
			foundProxy = ps
			break
		}
	}

	if foundProxy == nil {
		log.Printf("ProxyManager: UpdateProxyUserEnabledStatus - Proxy ID '%s' not found.", proxyID)
		return fmt.Errorf("proxy ID '%s' not found", proxyID)
	}

	newStatus := isEnabled
	statusChanged := false
	if foundProxy.UserEnabled == nil || *foundProxy.UserEnabled != newStatus {
		statusChanged = true
	}
	
	foundProxy.UserEnabled = &newStatus // Update the UserEnabled field

	log.Printf("ProxyManager: UserEnabled status for proxy ID '%s' (%s) set to %t.", proxyID, foundProxy.Address, newStatus)

	if statusChanged { // Only update active list if the enabled status actually changed
		pm.updateActiveProxies()
	}
	return nil
}

// IsProxyRelatedError checks if an error message suggests a proxy-related issue.
func IsProxyRelatedError(errStr string, proxyAddress string) bool {
    if errStr == "" {
        return false
    }
    lowerErr := strings.ToLower(errStr)
    // Specific proxy error substrings
    if strings.Contains(lowerErr, "proxyconnect") || 
       strings.Contains(lowerErr, "http: proxy error") || 
       strings.Contains(lowerErr, "socks connect") ||
       (proxyAddress != "" && strings.Contains(lowerErr, strings.ToLower(proxyAddress))) || // Error contains proxy address
       (proxyAddress != "" && strings.Contains(lowerErr, strings.ToLower(strings.Split(proxyAddress, ":")[0]))) { // Error contains proxy host
        return true
    }
    // Generic errors that are more likely proxy-related if a proxy was used
    if proxyAddress != "" { 
        if strings.Contains(lowerErr, "connect: connection refused") ||
           strings.Contains(lowerErr, "no such host") || // Could be proxy DNS failing
           strings.Contains(lowerErr, "context deadline exceeded") ||
           strings.Contains(lowerErr, "i/o timeout") ||
           strings.Contains(lowerErr, "unexpected eof") ||
           strings.Contains(lowerErr, "connection reset by peer") ||
           strings.Contains(lowerErr, "tls handshake timeout") {
            return true
        }
    }
    return false
}