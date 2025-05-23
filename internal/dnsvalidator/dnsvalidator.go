// File: backend/internal/dnsvalidator/dnsvalidator.go
package dnsvalidator

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fntelecomllc/domainflow/backend/internal/config"
	"github.com/miekg/dns"
)

type ResolverType int

const (
	SystemResolver ResolverType = iota
	StandardResolver
	DoHResolver
)

type ResolverClient struct {
	Address string
	Type    ResolverType
	Client  *http.Client // For DoH
	Dialer  *net.Dialer  // For standard UDP/TCP
}

type DNSValidator struct {
	config               config.DNSValidatorConfig
	activeResolvers      []ResolverClient
	weightedResolvers    []ResolverClient
	preferredOrderIdx    int
	currentRotationIdx   int
	mu                   sync.Mutex
}

func New(cfg config.DNSValidatorConfig) *DNSValidator {
	validator := &DNSValidator{
		config:             cfg,
		currentRotationIdx: 0,
		preferredOrderIdx:  0,
	}

	var allConfiguredResolvers []ResolverClient
	if cfg.UseSystemResolvers {
		sysConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err == nil && len(sysConfig.Servers) > 0 {
			for _, serverIP := range sysConfig.Servers {
				allConfiguredResolvers = append(allConfiguredResolvers, ResolverClient{
					Address: net.JoinHostPort(serverIP, sysConfig.Port), Type: SystemResolver,
					Dialer: &net.Dialer{Timeout: cfg.QueryTimeout},
				})
			}
		} else {
			if err != nil {
				log.Printf("DNSValidator: Warning - Could not load system resolvers: %v", err)
			}
		}
	}

	for _, rAddr := range cfg.Resolvers {
		if strings.HasPrefix(rAddr, "https://") {
			allConfiguredResolvers = append(allConfiguredResolvers, ResolverClient{
				Address: rAddr, Type: DoHResolver,
				Client: &http.Client{
					Timeout: cfg.QueryTimeout,
					Transport: &http.Transport{
						TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
						Proxy:               http.ProxyFromEnvironment,
						DialContext:         (&net.Dialer{Timeout: cfg.QueryTimeout, KeepAlive: 30 * time.Second}).DialContext,
						ForceAttemptHTTP2:   true,
						MaxIdleConns:        100,
						IdleConnTimeout:     90 * time.Second,
						TLSHandshakeTimeout: 10 * time.Second,
						ExpectContinueTimeout: 1 * time.Second,
					},
				},
			})
		} else {
			allConfiguredResolvers = append(allConfiguredResolvers, ResolverClient{
				Address: rAddr, Type: StandardResolver, Dialer: &net.Dialer{Timeout: cfg.QueryTimeout},
			})
		}
	}

	if cfg.ResolverStrategy == "sequential_failover" && len(cfg.ResolversPreferredOrder) > 0 {
		var preferredActive []ResolverClient
		for _, preferredAddr := range cfg.ResolversPreferredOrder {
			found := false
			for _, rClient := range allConfiguredResolvers {
				if rClient.Address == preferredAddr {
					preferredActive = append(preferredActive, rClient)
					found = true
					break
				}
			}
			if !found {
				log.Printf("DNSValidator: Warning - Preferred resolver '%s' not found.", preferredAddr)
			}
		}
		if len(preferredActive) > 0 {
			validator.activeResolvers = preferredActive
		} else {
			log.Printf("DNSValidator: Warning - No preferred resolvers valid. Falling back.")
			validator.activeResolvers = allConfiguredResolvers
		}
	} else {
		validator.activeResolvers = allConfiguredResolvers
	}

	if cfg.ResolverStrategy == "weighted_rotation" && len(cfg.ResolversWeighted) > 0 {
		var tempWeighted []ResolverClient
		for addr, weight := range cfg.ResolversWeighted {
			if weight <= 0 {
				continue
			}
			found := false
			for _, rClient := range allConfiguredResolvers {
				if rClient.Address == addr {
					for i := 0; i < weight; i++ {
						tempWeighted = append(tempWeighted, rClient)
					}
					found = true
					break
				}
			}
			if !found {
				log.Printf("DNSValidator: Warning - Weighted resolver '%s' not in main list.", addr)
			}
		}
		if len(tempWeighted) > 0 {
			validator.weightedResolvers = tempWeighted
			rand.Shuffle(len(validator.weightedResolvers), func(i, j int) {
				validator.weightedResolvers[i], validator.weightedResolvers[j] = validator.weightedResolvers[j], validator.weightedResolvers[i]
			})
		} else {
			log.Printf("DNSValidator: Warning - Weighted strategy chosen but no valid weighted resolvers.")
		}
	}

	if cfg.ResolverStrategy == "random_rotation" || (cfg.ResolverStrategy == "weighted_rotation" && len(validator.weightedResolvers) == 0) {
		if len(validator.activeResolvers) > 0 {
			rand.Shuffle(len(validator.activeResolvers), func(i, j int) {
				validator.activeResolvers[i], validator.activeResolvers[j] = validator.activeResolvers[j], validator.activeResolvers[i]
			})
		}
	}
	return validator
}

func (dv *DNSValidator) getNextResolver() (ResolverClient, error) {
	dv.mu.Lock()
	defer dv.mu.Unlock()
	switch dv.config.ResolverStrategy {
	case "weighted_rotation":
		if len(dv.weightedResolvers) > 0 {
			resolver := dv.weightedResolvers[dv.currentRotationIdx%len(dv.weightedResolvers)]
			dv.currentRotationIdx++
			return resolver, nil
		}
		if len(dv.activeResolvers) == 0 {
			return ResolverClient{}, fmt.Errorf("no DNS resolvers available (weighted fallback)")
		}
		resolver := dv.activeResolvers[dv.currentRotationIdx%len(dv.activeResolvers)]
		dv.currentRotationIdx++
		return resolver, nil
	case "sequential_failover":
		if len(dv.activeResolvers) == 0 {
			return ResolverClient{}, fmt.Errorf("no preferred DNS resolvers for sequential_failover")
		}
		if dv.preferredOrderIdx >= len(dv.activeResolvers) {
			return ResolverClient{}, fmt.Errorf("all preferred resolvers exhausted")
		}
		resolver := dv.activeResolvers[dv.preferredOrderIdx]
		return resolver, nil
	default: // random_rotation
		if len(dv.activeResolvers) == 0 {
			return ResolverClient{}, fmt.Errorf("no active DNS resolvers for random_rotation")
		}
		resolver := dv.activeResolvers[dv.currentRotationIdx%len(dv.activeResolvers)]
		dv.currentRotationIdx++
		return resolver, nil
	}
}

func (dv *DNSValidator) incrementPreferredOrderIdx() {
	dv.mu.Lock()
	defer dv.mu.Unlock()
	if dv.config.ResolverStrategy == "sequential_failover" && dv.preferredOrderIdx < len(dv.activeResolvers) {
		dv.preferredOrderIdx++
	}
}
func (dv *DNSValidator) resetPreferredOrderIdx() {
	dv.mu.Lock()
	dv.preferredOrderIdx = 0
	dv.mu.Unlock()
}

func (dv *DNSValidator) ValidateSingleDomain(domain string, ctx context.Context) ValidationResult {
	if dv.config.ResolverStrategy == "sequential_failover" {
		dv.resetPreferredOrderIdx()
		for {
			select {
			case <-ctx.Done():
				return ValidationResult{Domain: domain, Status: "Error", Error: "Context canceled before validation attempt", Timestamp: time.Now().Format(time.RFC3339)}
			default:
			}
			result := dv.performSingleDomainAttempt(domain, ctx)
			if result.Status == "Resolved" || result.Status == "Not Found" || !isPotentiallyRetryableError(result.Error) || ctx.Err() != nil {
				return result
			}
			dv.mu.Lock()
			canRetry := dv.preferredOrderIdx < len(dv.activeResolvers)-1
			dv.mu.Unlock()
			if !canRetry {
				return result
			}
			dv.incrementPreferredOrderIdx()
			log.Printf("DNSValidator: Domain %s failed with resolver %s (error: %s). Retrying with next preferred resolver.", domain, result.Resolver, result.Error)
		}
	}
	return dv.performSingleDomainAttempt(domain, ctx)
}

func isPotentiallyRetryableError(errMsg string) bool {
	if errMsg == "" {
		return false
	}
	lowerMsg := strings.ToLower(errMsg)
	if strings.Contains(lowerMsg, "no such host") || strings.Contains(lowerMsg, "nxdomain") || strings.Contains(lowerMsg, "name error") {
		return false
	}
	if strings.Contains(lowerMsg, "timeout") || strings.Contains(lowerMsg, "connection refused") || strings.Contains(lowerMsg, "i/o error") || strings.Contains(lowerMsg, "server misbehaving") || (strings.Contains(lowerMsg, "status 400") && !strings.Contains(lowerMsg, "parameter")) {
		return true
	}
	return false
}

func (dv *DNSValidator) performSingleDomainAttempt(domain string, ctx context.Context) ValidationResult {
	startTime := time.Now()
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return ValidationResult{Domain: domain, Status: "Error", Error: "Invalid domain format", Timestamp: startTime.Format(time.RFC3339), DurationMs: time.Since(startTime).Milliseconds()}
	}

	resolverClient, err := dv.getNextResolver()
	if err != nil {
		return ValidationResult{Domain: domain, Status: "Error", Error: "Failed to get resolver: " + err.Error(), Timestamp: startTime.Format(time.RFC3339), DurationMs: time.Since(startTime).Milliseconds()}
	}

	if dv.config.QueryDelayMin > 0 && dv.config.QueryDelayMax > 0 && dv.config.QueryDelayMax >= dv.config.QueryDelayMin {
		delayRange := dv.config.QueryDelayMax - dv.config.QueryDelayMin
		randomDelay := dv.config.QueryDelayMin
		if delayRange > 0 {
			randomDelay += time.Duration(rand.Int63n(int64(delayRange)))
		}
		select {
		case <-time.After(randomDelay):
		case <-ctx.Done():
			return ValidationResult{Domain: domain, Status: "Error", Error: "Context canceled during query delay", Resolver: resolverClient.Address, Timestamp: startTime.Format(time.RFC3339), DurationMs: time.Since(startTime).Milliseconds()}
		}
	}

	var primaryError error
	var wgQueryTypes sync.WaitGroup
	queryResultsChan := make(chan queryTypeResult, 2)

	recordTypesToQuery := []uint16{dns.TypeA, dns.TypeAAAA}
	domainQuerySemaphore := make(chan struct{}, dv.config.ConcurrentQueriesPerDomain)

	select {
	case <-ctx.Done():
		return ValidationResult{Domain: domain, Status: "Error", Error: "Context canceled before starting queries for domain: " + ctx.Err().Error(), Resolver: resolverClient.Address, Timestamp: startTime.Format(time.RFC3339), DurationMs: time.Since(startTime).Milliseconds()}
	default:
	}

	for _, recordType := range recordTypesToQuery {
		select {
		case <-ctx.Done():
			if primaryError == nil {
				primaryError = fmt.Errorf("context canceled before launching query type %d for domain %s: %w", recordType, domain, ctx.Err())
			}
			goto processResultsLoopExit
		default:
		}

		wgQueryTypes.Add(1)
		domainQuerySemaphore <- struct{}{}
		go func(rType uint16) {
			defer wgQueryTypes.Done()
			defer func() { <-domainQuerySemaphore }()

			var ips []string
			var errQuery error
			queryCtx, queryCancel := context.WithCancel(ctx)
			defer queryCancel()

			switch resolverClient.Type {
			case SystemResolver, StandardResolver:
				ips, errQuery = dv.resolveStandardType(queryCtx, domain, rType, resolverClient)
			case DoHResolver:
				ips, errQuery = dv.queryDoHRecord(queryCtx, domain, rType, resolverClient)
			default:
				errQuery = fmt.Errorf("unknown resolver type for %s", resolverClient.Address)
			}
			queryResultsChan <- queryTypeResult{ips: ips, err: errQuery, recordType: rType}
		}(recordType)
	}
processResultsLoopExit:

	wgQueryTypes.Wait()
	close(queryResultsChan)

	var collectedA, collectedAAAA []string
	var errA, errAAAA error

	for res := range queryResultsChan {
		if res.recordType == dns.TypeA {
			collectedA = res.ips
			errA = res.err
		}
		if res.recordType == dns.TypeAAAA {
			collectedAAAA = res.ips
			errAAAA = res.err
		}
	}

	finalIPs := append(collectedA, collectedAAAA...)

	if primaryError == nil {
		if len(finalIPs) == 0 {
			if errA != nil && errAAAA != nil {
				if isNXDOMAIN(errA) || (!isNXDOMAIN(errAAAA) && isTimeout(errAAAA) && !isTimeout(errA)) {
					primaryError = errA
				} else {
					primaryError = errAAAA
				}
			} else if errA != nil {
				primaryError = errA
			} else if errAAAA != nil {
				primaryError = errAAAA
			} else {
				primaryError = fmt.Errorf("no A or AAAA records found (no specific query errors)")
			}
		}
	}

	duration := time.Since(startTime)
	result := ValidationResult{
		Domain:     domain,
		Resolver:   resolverClient.Address,
		Timestamp:  startTime.Format(time.RFC3339),
		DurationMs: duration.Milliseconds(),
	}

	if primaryError != nil {
		result.Status = "Error" // Default status if error occurred
		if dnsErr, ok := primaryError.(*net.DNSError); ok {
			// If it's a net.DNSError, refine status
			if dnsErr.IsNotFound {
				result.Status = "Not Found"
			}
			// Check for timeout separately, can overwrite "Not Found" if both (though unusual for std dnsErr)
			if dnsErr.IsTimeout {
				result.Status = "Timeout"
			}
		} else if isNXDOMAIN(primaryError) { // Not a net.DNSError, check custom NXDOMAIN
			result.Status = "Not Found"
		} else if isTimeout(primaryError) { // Not a net.DNSError, check custom Timeout
			result.Status = "Timeout"
		} else if strings.Contains(primaryError.Error(), "context canceled") {
			result.Status = "Cancelled"
		}
		// If none of the specific conditions above changed status, it remains "Error"
		result.Error = primaryError.Error()
	} else {
		// No primary error, determine status based on IPs
		if len(finalIPs) > 0 {
			result.Status = "Resolved"
			result.IPs = deduplicateIPs(finalIPs)
		} else {
			result.Status = "Not Found"
			result.Error = "No A or AAAA records found (final check, no primary error)"
		}
	}
	return result
}

type queryTypeResult struct {
	ips        []string
	err        error
	recordType uint16
}

func isNXDOMAIN(err error) bool {
	if err == nil {
		return false
	}
	if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
		return true
	}
	lowerMsg := strings.ToLower(err.Error())
	return strings.Contains(lowerMsg, "no such host") || strings.Contains(lowerMsg, "nxdomain") || strings.Contains(lowerMsg, "name error")
}
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsTimeout {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout") || strings.Contains(strings.ToLower(err.Error()), "context deadline exceeded")
}

func (dv *DNSValidator) resolveStandardType(ctx context.Context, domain string, recordType uint16, resolver ResolverClient) ([]string, error) {
	r := &net.Resolver{PreferGo: true,
		Dial: func(dCtx context.Context, network, address string) (net.Conn, error) {
			return resolver.Dialer.DialContext(dCtx, network, resolver.Address)
		},
	}
	ipAddrs, err := r.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}
	var ipsFound []string
	for _, ipAddr := range ipAddrs {
		if recordType == dns.TypeA && ipAddr.IP.To4() != nil {
			ipsFound = append(ipsFound, ipAddr.IP.String())
		}
		if recordType == dns.TypeAAAA && ipAddr.IP.To4() == nil && ipAddr.IP.To16() != nil {
			ipsFound = append(ipsFound, ipAddr.IP.String())
		}
	}
	return ipsFound, nil
}

func (dv *DNSValidator) queryDoHRecord(ctx context.Context, domain string, recordType uint16, resolver ResolverClient) ([]string, error) {
	queryDomain := dns.Fqdn(domain)
	dohURLString := resolver.Address
	if strings.HasPrefix(resolver.Address, "https://dns.google/dns-query") {
		dohURLString = "https://dns.google/resolve"
	}

	dohURL, err := url.Parse(dohURLString)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL %s: %w", dohURLString, err)
	}

	query := dohURL.Query()
	query.Set("name", queryDomain)
	query.Set("type", dns.TypeToString[recordType])
	dohURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", dohURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("DoH: create request failed for %s: %w", domain, err)
	}

	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36")

	resp, err := resolver.Client.Do(req)
	if err != nil {
		if ctx.Err() == context.Canceled {
			return nil, fmt.Errorf("DoH: request for %s context canceled: %w", domain, ctx.Err())
		}
		if ctx.Err() == context.DeadlineExceeded {
			return nil, &net.DNSError{Err: "timeout", Name: domain, Server: resolver.Address, IsTimeout: true}
		}
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsTimeout {
			return nil, err
		}
		if urlErr, ok := err.(*url.Error); ok && urlErr.Timeout() {
			return nil, &net.DNSError{Err: "timeout", Name: domain, Server: resolver.Address, IsTimeout: true}
		}
		return nil, fmt.Errorf("DoH: request failed for %s type %s using %s: %w", domain, dns.TypeToString[recordType], resolver.Address, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("DoH: request for %s type %s returned status %d using %s. Body: %s", domain, dns.TypeToString[recordType], resp.StatusCode, resolver.Address, string(bodyBytes))
	}

	var dohResp DoHJSONResponse
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("DoH: read body failed for %s: %w", domain, err)
	}
	if err := json.Unmarshal(bodyBytes, &dohResp); err != nil {
		bodySnippet := string(bodyBytes)
		if len(bodySnippet) > 512 {
			bodySnippet = bodySnippet[:512]
		}
		return nil, fmt.Errorf("DoH: decode JSON failed for %s (preview: %s): %w", domain, bodySnippet, err)
	}

	if dohResp.Status != dns.RcodeSuccess {
		if dohResp.Status == dns.RcodeNameError {
			return nil, &net.DNSError{Err: "no such host", Name: domain, Server: resolver.Address, IsNotFound: true}
		}
		return nil, fmt.Errorf("DoH server %s returned RCODE %d (%s) for %s type %s", resolver.Address, dohResp.Status, dns.RcodeToString[dohResp.Status], domain, dns.TypeToString[recordType])
	}

	var ips []string
	if dohResp.Answer != nil {
		for _, answer := range dohResp.Answer {
			if answer.Type == int(recordType) && strings.TrimSuffix(answer.Name, ".") == strings.TrimSuffix(queryDomain, ".") {
				parsedIP := net.ParseIP(answer.Data)
				if parsedIP != nil {
					isV4 := parsedIP.To4() != nil
					isV6 := parsedIP.To16() != nil && !isV4
					if recordType == dns.TypeA && isV4 {
						ips = append(ips, answer.Data)
					}
					if recordType == dns.TypeAAAA && isV6 {
						ips = append(ips, answer.Data)
					}
				}
			}
		}
	}
	return ips, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func deduplicateIPs(ips []string) []string {
	seen := make(map[string]struct{}, len(ips))
	j := 0
	for _, ip := range ips {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		ips[j] = ip
		j++
	}
	return ips[:j]
}

type DoHAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}
type DoHJSONResponse struct {
	Status   int    `json:"Status"`
	TC       bool   `json:"TC"`
	RD       bool   `json:"RD"`
	RA       bool   `json:"RA"`
	AD       bool   `json:"AD"`
	CD       bool   `json:"CD"`
	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	} `json:"Question"`
	Answer []DoHAnswer `json:"Answer,omitempty"`
}

func (dv *DNSValidator) ValidateDomains(domains []string) []ValidationResult {
	noResolversAvailable := false
	if dv.config.ResolverStrategy == "weighted_rotation" {
		if len(dv.weightedResolvers) == 0 && len(dv.activeResolvers) == 0 {
			noResolversAvailable = true
		}
	} else {
		if len(dv.activeResolvers) == 0 {
			noResolversAvailable = true
		}
	}
	if noResolversAvailable {
		results := make([]ValidationResult, len(domains))
		for i, domain := range domains {
			results[i] = ValidationResult{Domain: domain, Status: "Error", Error: "No DNS resolvers available", Timestamp: time.Now().Format(time.RFC3339)}
		}
		return results
	}
	results := make([]ValidationResult, len(domains))
	var wg sync.WaitGroup
	batchSemaphore := make(chan struct{}, dv.config.MaxConcurrentGoroutines)
	for i, domain := range domains {
		wg.Add(1)
		batchSemaphore <- struct{}{}
		go func(idx int, d string) {
			defer wg.Done()
			defer func() { <-batchSemaphore }()
			domainCtx, domainCancel := context.WithTimeout(context.Background(), dv.config.QueryTimeout*2+dv.config.QueryDelayMax*2+time.Second*2)
			defer domainCancel()
			if dv.config.ResolverStrategy == "sequential_failover" {
				dv.resetPreferredOrderIdx()
			}
			results[idx] = dv.ValidateSingleDomain(d, domainCtx)
		}(i, domain)
	}
	wg.Wait()
	return results
}
