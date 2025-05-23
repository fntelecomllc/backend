package contentfetcher

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"bytes"
	"compress/gzip"
	"compress/zlib"

	"github.com/fntelecomllc/domainflow/backend/internal/config"
	"github.com/fntelecomllc/domainflow/backend/internal/proxymanager"
	"golang.org/x/net/html/charset"
)

// ContentFetcher is responsible for fetching URL content with persona and proxy support.
type ContentFetcher struct {
	appConfig *config.AppConfig
	proxyMgr  *proxymanager.ProxyManager
}

// NewContentFetcher creates a new ContentFetcher.
func NewContentFetcher(appCfg *config.AppConfig, proxyMgr *proxymanager.ProxyManager) *ContentFetcher {
	if appCfg == nil {
		log.Println("ContentFetcher Warning: appConfig is nil during construction. Default settings will be minimal.")
		// Initialize with minimal defaults to prevent panics if used without full config
		appCfg = &config.AppConfig{
			HTTPValidator: config.HTTPValidatorConfig{
				RequestTimeout: 30 * time.Second,
				MaxRedirects:   7,
			},
		}
	}
	return &ContentFetcher{
		appConfig: appCfg,
		proxyMgr:  proxyMgr,
	}
}

// Fetch attempts to retrieve content for a given URL, applying HTTP and DNS personas.
// It returns the body, final URL, status code, actual HTTP Persona ID used, actual DNS Persona ID used, and any error.
func (cf *ContentFetcher) Fetch(
	ctx context.Context,
	urlStr string,
	httpPersonaID *string,
	dnsPersonaID *string,
) (body []byte, finalURL string, statusCode int, httpPersonaIDUsed *string, dnsPersonaIDUsed *string, err error) {

	httpClient, actualUserAgent, actualHeaders, _, usedProxy, resolvedDNSPersonaID := cf.createConfiguredClient(ctx, httpPersonaID, dnsPersonaID)

	httpPersonaIDUsed = httpPersonaID // Assume requested is used; createConfiguredClient might log if not found
	dnsPersonaIDUsed = resolvedDNSPersonaID // This comes from createConfiguredClient based on successful lookup


	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr // Default to HTTPS if no scheme
	}

	var urlsToTry []string
	if strings.HasPrefix(urlStr, "https://") {
		urlsToTry = append(urlsToTry, urlStr)
		httpAttemptURL := strings.Replace(urlStr, "https://", "http://", 1)
		if httpAttemptURL != urlStr {
			urlsToTry = append(urlsToTry, httpAttemptURL)
		}
	} else { // Assuming "http://"
		urlsToTry = append(urlsToTry, urlStr)
		httpsAttemptURL := strings.Replace(urlStr, "http://", "https://", 1)
		if httpsAttemptURL != urlStr {
			urlsToTry = append([]string{httpsAttemptURL}, urlsToTry...) // Prepend HTTPS attempt
		}
	}

	var resp *http.Response
	var reqError error
	var attemptURL string

	for _, currentURLToTry := range urlsToTry {
		attemptURL = currentURLToTry
		proxyLogStr := "direct"
		if usedProxy != nil {
			proxyLogStr = fmt.Sprintf("proxy %s (%s)", usedProxy.ID, usedProxy.Address)
		}
		dnsLogStr := "system DNS"
		if dnsPersonaIDUsed != nil && *dnsPersonaIDUsed != "" {
			dnsLogStr = fmt.Sprintf("DNS Persona %s", *dnsPersonaIDUsed)
		}
		log.Printf("ContentFetcher: Attempting URL: %s (UA: %s, %s, %s)", attemptURL, actualUserAgent, proxyLogStr, dnsLogStr)
		
		req, errNewReq := http.NewRequestWithContext(ctx, "GET", attemptURL, nil)
		if errNewReq != nil {
			reqError = fmt.Errorf("failed to create request for %s: %w", attemptURL, errNewReq)
			continue
		}

		req.Header.Set("User-Agent", actualUserAgent)
		for key, value := range actualHeaders {
			req.Header.Set(key, value)
		}
		if _, ok := actualHeaders["Accept"]; !ok {
            req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		}
		if _, ok := actualHeaders["Accept-Language"]; !ok {
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		}


		currentResp, doErr := httpClient.Do(req)
		if doErr != nil {
			reqError = fmt.Errorf("request to %s failed: %w", attemptURL, doErr)
			if currentResp != nil {
				io.Copy(ioutil.Discard, currentResp.Body)
				currentResp.Body.Close()
			}
			if ctx.Err() != nil {
				return nil, "", 0, httpPersonaIDUsed, dnsPersonaIDUsed, fmt.Errorf("context cancelled during request to %s: %w", attemptURL, ctx.Err())
			}
			continue
		}

		resp = currentResp
		reqError = nil
		break
	}

	if reqError != nil {
		err = reqError
		if usedProxy != nil && cf.proxyMgr != nil && proxymanager.IsProxyRelatedError(err.Error(), usedProxy.Address) {
			cf.proxyMgr.ReportProxyHealth(usedProxy.ID, false, err)
		}
		return nil, "", 0, httpPersonaIDUsed, dnsPersonaIDUsed, err
	}

	if resp == nil {
		err = fmt.Errorf("no response received after trying: %s", strings.Join(urlsToTry, ", "))
		return nil, "", 0, httpPersonaIDUsed, dnsPersonaIDUsed, err
	}

	defer func() {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}()

	finalURL = resp.Request.URL.String() // URL after redirects
	statusCode = resp.StatusCode

	if usedProxy != nil && cf.proxyMgr != nil {
		// Consider the call successful for the proxy if we got a response, regardless of status code, unless it's a clear proxy error handled above.
		cf.proxyMgr.ReportProxyHealth(usedProxy.ID, true, nil)
	}

	// Robust body reading with decompression, charset conversion, and size limits.
	var processedBody []byte
	var bodyReadError error

	decompressedReader := resp.Body
	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "gzip":
		gzReader, errGzip := gzip.NewReader(resp.Body)
		if errGzip != nil {
			bodyReadError = fmt.Errorf("gzip reader error for %s: %w", finalURL, errGzip)
		} else {
			defer gzReader.Close()
			decompressedReader = gzReader
		}
	case "deflate":
		zlibReader, errZlib := zlib.NewReader(resp.Body)
		if errZlib != nil {
			bodyReadError = fmt.Errorf("deflate reader error for %s: %w", finalURL, errZlib)
		} else {
			defer zlibReader.Close()
			decompressedReader = zlibReader
		}
	}

	if bodyReadError != nil {
		return nil, finalURL, statusCode, httpPersonaIDUsed, dnsPersonaIDUsed, bodyReadError
	}

	// Limit the size of the body read for keyword extraction to prevent OOM issues with huge pages.
	// This limit should be configurable if necessary.
	const maxBodyReadBytesForKeywordExtraction = 10 * 1024 * 1024 // 10MB limit
	limitedReader := io.LimitReader(decompressedReader, maxBodyReadBytesForKeywordExtraction)
	rawBodyBytes, readErr := ioutil.ReadAll(limitedReader)

	if readErr != nil && readErr != io.EOF {
		bodyReadError = fmt.Errorf("error reading response body from %s (limit %dMB): %w", finalURL, maxBodyReadBytesForKeywordExtraction/(1024*1024), readErr)
		return nil, finalURL, statusCode, httpPersonaIDUsed, dnsPersonaIDUsed, bodyReadError
	}

	// Convert to UTF-8
	contentType := resp.Header.Get("Content-Type")
	utf8Reader, errConv := charset.NewReader(bytes.NewReader(rawBodyBytes), contentType)
	if errConv != nil {
		log.Printf("ContentFetcher: Could not get UTF-8 reader for %s (ContentType: '%s'): %v. Using raw bytes.", finalURL, contentType, errConv)
		processedBody = rawBodyBytes // Use raw bytes if charset conversion setup fails
	} else {
		utf8Bytes, errReadUTF8 := ioutil.ReadAll(utf8Reader)
		if errReadUTF8 != nil {
			log.Printf("ContentFetcher: Error reading as UTF-8 from %s: %v. Using raw bytes from initial read.", finalURL, errReadUTF8)
			processedBody = rawBodyBytes // Use raw (but decompressed and limited) bytes if UTF-8 conversion read fails
		} else {
			processedBody = utf8Bytes
		}
	}
	
	log.Printf("ContentFetcher: Successfully fetched and processed %s (Status: %d, Processed Size: %d bytes, Final URL: %s)", urlStr, statusCode, len(processedBody), finalURL)
	return processedBody, finalURL, statusCode, httpPersonaIDUsed, dnsPersonaIDUsed, nil
}

// createConfiguredClient configures an *http.Client based on HTTP and DNS personas, and proxy settings.
// Returns the client, effective User-Agent, effective Headers, chosen proxy, and the ID of the DNS persona used (if any).
func (cf *ContentFetcher) createConfiguredClient(
	ctx context.Context,
	httpPersonaID *string,
	dnsPersonaIDInput *string,
) (client *http.Client, userAgent string, headers map[string]string, maxRedirects int, usedProxy *config.ProxyConfigEntry, actualDNSPersonaID *string) {
	
	// Ensure cf.appConfig and cf.appConfig.HTTPValidator are not nil
    if cf.appConfig == nil {
        // This case should ideally be handled by NewContentFetcher, but as a safeguard:
        log.Println("ContentFetcher Critical: appConfig is nil in createConfiguredClient.")
        // Return a very basic client to avoid panic
        return &http.Client{Timeout: 30 * time.Second}, "DomainFlowBot/1.0 (EmergencyDefault)", make(map[string]string), 7, nil, nil
    }


	serverDefaultHTTPCfg := cf.appConfig.HTTPValidator
	allLoadedHTTPPersonas := cf.appConfig.HTTPPersonas
	allLoadedDNSPersonas := cf.appConfig.DNSPersonas

	var effectiveUserAgent string
	var effectiveHeaders map[string]string = make(map[string]string)
	var effectiveMaxRedirects int = serverDefaultHTTPCfg.MaxRedirects
	var effectiveAllowInsecureTLS bool = serverDefaultHTTPCfg.AllowInsecureTLS
	var effectiveCookieMode string = "session"
	var effectiveTLSConfig *tls.Config = &tls.Config{} // Initialize to avoid nil pointer
	var effectiveForceHTTP2 bool = true

	if httpPersonaID != nil && *httpPersonaID != "" {
		var chosenHTTPPersona *config.HTTPPersona
		for i := range allLoadedHTTPPersonas {
			if allLoadedHTTPPersonas[i].ID == *httpPersonaID {
				pCopy := allLoadedHTTPPersonas[i]
				chosenHTTPPersona = &pCopy
				break
			}
		}
		if chosenHTTPPersona != nil {
			log.Printf("ContentFetcher: Applying HTTP Persona '%s'", *httpPersonaID)
			effectiveUserAgent = chosenHTTPPersona.UserAgent
			if chosenHTTPPersona.Headers != nil {
				for k, v := range chosenHTTPPersona.Headers {
					effectiveHeaders[k] = v
				}
			}
			// MaxRedirects and AllowInsecureTLS will use server defaults for now,
			// as these fields are not yet in config.HTTPPersona struct.
			// To be added to HTTPPersona later.
			if chosenHTTPPersona.CookieHandling.Mode != "" {
				effectiveCookieMode = chosenHTTPPersona.CookieHandling.Mode
			}
			if chosenHTTPPersona.HTTP2Settings.Enabled != nil {
				effectiveForceHTTP2 = *chosenHTTPPersona.HTTP2Settings.Enabled
			}
			
			tlsClientHello := chosenHTTPPersona.TLSClientHello
			if tlsClientHello.MinVersion != "" || tlsClientHello.MaxVersion != "" || len(tlsClientHello.CipherSuites) > 0 || len(tlsClientHello.CurvePreferences) > 0 {
				if v, ok := config.GetTLSVersion(tlsClientHello.MinVersion); ok && v != 0 {
					effectiveTLSConfig.MinVersion = v
				}
				if v, ok := config.GetTLSVersion(tlsClientHello.MaxVersion); ok && v != 0 {
					effectiveTLSConfig.MaxVersion = v
				}
				if s, err := config.GetCipherSuites(tlsClientHello.CipherSuites); err == nil && len(s) > 0 {
					effectiveTLSConfig.CipherSuites = s
				} else if err != nil {
					log.Printf("ContentFetcher: Warn - HTTP Persona '%s' invalid ciphers: %v", *httpPersonaID, err)
				}
				if c, err := config.GetCurvePreferences(tlsClientHello.CurvePreferences); err == nil && len(c) > 0 {
					effectiveTLSConfig.CurvePreferences = c
				} else if err != nil {
					log.Printf("ContentFetcher: Warn - HTTP Persona '%s' invalid curves: %v", *httpPersonaID, err)
				}
			}
		} else {
			log.Printf("ContentFetcher: HTTP Persona ID '%s' not found. Using server defaults for HTTP config.", *httpPersonaID)
		}
	}

	if effectiveUserAgent == "" {
		if len(serverDefaultHTTPCfg.UserAgents) > 0 {
			effectiveUserAgent = serverDefaultHTTPCfg.UserAgents[rand.Intn(len(serverDefaultHTTPCfg.UserAgents))]
		} else {
			effectiveUserAgent = "DomainFlowContentFetcher/1.0 (DefaultUA)"
		}
	}
	if len(effectiveHeaders) == 0 && serverDefaultHTTPCfg.DefaultHeaders != nil {
		 for k, v := range serverDefaultHTTPCfg.DefaultHeaders {
			effectiveHeaders[k] = v
		 }
	}
	effectiveTLSConfig.InsecureSkipVerify = effectiveAllowInsecureTLS


	// --- DNS Resolver Configuration ---
	var dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)
	// Start with a default dialer
	defaultDialer := &net.Dialer{
		Timeout:   30 * time.Second, // Default connection timeout
		KeepAlive: 30 * time.Second,
	}
	dialContextFunc = defaultDialer.DialContext // Standard dial context initially

	if dnsPersonaIDInput != nil && *dnsPersonaIDInput != "" {
		var chosenDNSPersona *config.DNSPersona
		for i := range allLoadedDNSPersonas { // Iterate by index for safe copy
			if allLoadedDNSPersonas[i].ID == *dnsPersonaIDInput {
				pCopy := allLoadedDNSPersonas[i]
				chosenDNSPersona = &pCopy
				break
			}
		}

		if chosenDNSPersona != nil && len(chosenDNSPersona.Config.Resolvers) > 0 {
			log.Printf("ContentFetcher: Applying DNS Persona '%s' with resolvers: %v", *dnsPersonaIDInput, chosenDNSPersona.Config.Resolvers)
			actualDNSPersonaID = dnsPersonaIDInput // Set the actual DNS persona ID used

			// Create a custom resolver that will use the persona's DNS servers
			customResolver := &net.Resolver{
				PreferGo: true, // Use Go's resolver to ensure custom Dial func is called
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					// This Dial func is for the resolver *itself* when it needs to connect to a DNS server.
					// It will iterate through the persona's DNS servers.
					var lastErr error
					for _, resolverAddr := range chosenDNSPersona.Config.Resolvers {
						if !strings.Contains(resolverAddr, ":") { // Ensure port, default 53 for DNS
							resolverAddr = net.JoinHostPort(resolverAddr, "53")
						}
						
						personaDNSTimeout := time.Duration(chosenDNSPersona.Config.QueryTimeoutSeconds) * time.Second
						if personaDNSTimeout <= 0 {
							personaDNSTimeout = 5 * time.Second // Fallback timeout for DNS query
						}
						d := net.Dialer{Timeout: personaDNSTimeout}

						log.Printf("ContentFetcher (DNS Resolver Dial): Attempting to connect to DNS server %s for %s network", resolverAddr, network)
						conn, err := d.DialContext(ctx, network, resolverAddr) // network is usually "udp" or "tcp"
						if err == nil {
							log.Printf("ContentFetcher (DNS Resolver Dial): Successfully connected to DNS server %s", resolverAddr)
							return conn, nil
						}
						log.Printf("ContentFetcher (DNS Resolver Dial): Failed to connect to DNS server %s: %v", resolverAddr, err)
						lastErr = err
					}
					return nil, fmt.Errorf("failed to connect to any DNS server for persona %s: %w", *dnsPersonaIDInput, lastErr)
				},
			}
			
			// Now, the transport's DialContext needs to use this customResolver for lookups.
			dialContextFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("DNS Persona DialContext: failed to split host/port from address '%s': %w", addr, err)
				}

				var targetIPs []string
				if net.ParseIP(host) == nil { // If host is not an IP address, resolve it using custom resolver
					log.Printf("ContentFetcher (Transport DialContext): Resolving host '%s' using DNS Persona '%s'", host, *actualDNSPersonaID)
					ips, resolveErr := customResolver.LookupIPAddr(ctx, host)
					if resolveErr != nil {
						return nil, fmt.Errorf("DNS Persona '%s' custom resolution failed for %s: %w", *actualDNSPersonaID, host, resolveErr)
					}
					if len(ips) == 0 {
						return nil, fmt.Errorf("DNS Persona '%s' custom resolution for %s returned no IPs", *actualDNSPersonaID, host)
					}
					for _, ipAddr := range ips {
						targetIPs = append(targetIPs, ipAddr.String())
					}
					log.Printf("ContentFetcher (Transport DialContext): DNS Persona '%s' resolved '%s' to %v", *actualDNSPersonaID, host, targetIPs)
				} else {
					targetIPs = []string{host} // Host is already an IP
					log.Printf("ContentFetcher (Transport DialContext): Host '%s' is already an IP, bypassing DNS Persona lookup.", host)
				}
				
				// Connect to the first resolved IP.
				// A more robust implementation might try multiple resolved IPs.
				connectDialer := &net.Dialer{ // Use a standard dialer for the actual TCP/UDP connection
                    Timeout:   serverDefaultHTTPCfg.RequestTimeout, // Use general request timeout for connection attempt
                    KeepAlive: 30 * time.Second,                    // Standard keep-alive
                }
				finalConnectAddr := net.JoinHostPort(targetIPs[0], port)
				log.Printf("ContentFetcher (Transport DialContext): Connecting to resolved address: %s (network: %s)", finalConnectAddr, network)
				return connectDialer.DialContext(ctx, network, finalConnectAddr)
			}
		} else if chosenDNSPersona == nil && dnsPersonaIDInput != nil && *dnsPersonaIDInput != "" {
			log.Printf("ContentFetcher: DNS Persona ID '%s' not found. Using default system DNS.", *dnsPersonaIDInput)
		} else if chosenDNSPersona != nil && len(chosenDNSPersona.Config.Resolvers) == 0 {
			log.Printf("ContentFetcher: DNS Persona '%s' has no resolvers. Using default system DNS.", *dnsPersonaIDInput)
		}
	} else {
		log.Printf("ContentFetcher: No DNS Persona ID provided. Using default system DNS.")
	}


	// --- Transport and Proxy Configuration ---
	baseTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialContextFunc, // This will use either default or DNS persona-configured dialer
		TLSClientConfig:       effectiveTLSConfig,
		ForceAttemptHTTP2:     effectiveForceHTTP2,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   10, // Added for better connection pooling
        ResponseHeaderTimeout: serverDefaultHTTPCfg.RequestTimeout, // Timeout for reading response headers
	}

	currentRoundTripper := http.RoundTripper(baseTransport)
	if cf.proxyMgr != nil {
		pEntry, err := cf.proxyMgr.GetProxy()
		if err == nil && pEntry != nil {
			log.Printf("ContentFetcher: Attempting to use proxy ID '%s' (%s://%s)", pEntry.ID, pEntry.Protocol, pEntry.Address)
			// GetHTTPTransportForProxy should take the existing baseTransport and wrap it for proxying
			// It should preserve the DialContext, TLSClientConfig etc. from baseTransport.
			proxyTransport, errTransport := proxymanager.GetHTTPTransportForProxy(pEntry, baseTransport)
			if errTransport == nil && proxyTransport != nil {
				currentRoundTripper = proxyTransport
				usedProxy = pEntry
				log.Printf("ContentFetcher: Successfully configured transport with proxy ID '%s'", pEntry.ID)
			} else {
				log.Printf("ContentFetcher: Failed to get/configure transport for proxy ID '%s': %v. Using direct transport.", pEntry.ID, errTransport)
			}
		} else {
			log.Printf("ContentFetcher: No healthy proxy available from ProxyManager (%v). Using direct transport.", err)
		}
	} else {
		log.Printf("ContentFetcher: ProxyManager is nil. Using direct transport.")
	}

	var jar http.CookieJar
	if strings.ToLower(effectiveCookieMode) == "session" {
		var jarErr error
		jar, jarErr = cookiejar.New(nil)
		if jarErr != nil {
			log.Printf("ContentFetcher: Error creating cookie jar: %v", jarErr)
		}
	}

	finalClient := &http.Client{
		Transport: currentRoundTripper,
		Jar:       jar,
		Timeout:   serverDefaultHTTPCfg.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= effectiveMaxRedirects {
				return http.ErrUseLastResponse
			}
			// Log redirect
			// log.Printf("ContentFetcher: Redirecting from %s to %s (attempt %d/%d)", via[len(via)-1].URL, req.URL, len(via), effectiveMaxRedirects)
			return nil
		},
	}
	return finalClient, effectiveUserAgent, effectiveHeaders, effectiveMaxRedirects, usedProxy, actualDNSPersonaID
}

// TODO: Add a function similar to httpvalidator's body reading logic:
// func readAndProcessBody(resp *http.Response, maxBodyReadBytes int64) ([]byte, string, error)
// This function should handle:
// 1. Content-Encoding (gzip, deflate)
// 2. Charset detection and conversion to UTF-8 (using golang.org/x/net/html/charset)
// 3. Limiting read size (maxBodyReadBytes)
// 4. Returning the processed (UTF-8, decompressed) body and any content hash error.
// The current Fetch method uses a simple ioutil.ReadAll which is insufficient.
