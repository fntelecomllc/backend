// File: backend/cmd/apiserver/main.go
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/fntelecomllc/domainflow/backend/internal/api"
	"github.com/fntelecomllc/domainflow/backend/internal/config"
	"github.com/fntelecomllc/domainflow/backend/internal/proxymanager" // Import the new package

	_ "net/http/pprof" // For profiling, if needed
)

const (
	defaultPort    = "8080"
	configFilePath = "config.json"
	// Default timeout for individual proxy health checks (if ProxyManager were to do them)
	// For now, this is passed to NewProxyManager but not actively used by background checks yet.
	defaultProxyHealthCheckTimeout = 10 * time.Second
)

func main() {
	appConfig, err := config.Load(configFilePath)
	if err != nil {
		log.Printf("Main: Notice during config.Load: %v. Application will proceed with available/defaulted config.", err)
	}
	if appConfig == nil {
		log.Fatalf("CRITICAL: Configuration could not be loaded by config.Load, and no defaults were returned. Exiting.")
	}

	// --- API Key Configuration ---
	loadedAPIKeyFromFile := appConfig.Server.APIKey
	apiKeyFromEnv := os.Getenv("DOMAINFLOW_API_KEY")
	if apiKeyFromEnv != "" {
		appConfig.Server.APIKey = apiKeyFromEnv
		log.Printf("API Key: Using value from DOMAINFLOW_API_KEY environment variable (length: %d).", len(appConfig.Server.APIKey))
	} else {
		if loadedAPIKeyFromFile == "" {
			log.Printf("API Key: Empty in config.json and no ENV override. Using system default placeholder.")
			appConfig.Server.APIKey = config.DefaultSystemAPIKeyPlaceholder
		} else {
			appConfig.Server.APIKey = loadedAPIKeyFromFile
		}
	}
	if appConfig.Server.APIKey == config.DefaultSystemAPIKeyPlaceholder {
		log.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		log.Println("!!! WARNING: API Key is the default system placeholder. THIS IS INSECURE.       !!!")
		log.Println("!!! Please set a unique 'server.apiKey' in 'config.json' or use               !!!")
		log.Println("!!! the 'DOMAINFLOW_API_KEY' environment variable for production deployments.   !!!")
		log.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	}

	// --- Port Configuration ---
	if appConfig.Server.Port == "" {
		appConfig.Server.Port = defaultPort
	}
	if portEnv := os.Getenv("DOMAINFLOW_PORT"); portEnv != "" {
		appConfig.Server.Port = portEnv
		log.Printf("Port: Overridden by DOMAINFLOW_PORT environment variable: %s", portEnv)
	}

	// --- Initialize ProxyManager ---
	// The health check timeout passed here is for potential future background checks within ProxyManager.
	// The ProxyManager.TestProxy function uses its own ProxyTestTimeout constant.
	log.Printf("Main: Initializing ProxyManager with %d configured proxies.", len(appConfig.Proxies))
	proxyMgr := proxymanager.NewProxyManager(appConfig.Proxies, defaultProxyHealthCheckTimeout)
	// TODO: In the future, if ProxyManager has a StartBackgroundHealthChecks method:
	// go proxyMgr.StartBackgroundHealthChecks( /* interval */ )

	// --- Initialize Router and HTTP Server ---
	// Pass both appConfig and proxyMgr to NewRouter, which will then pass them to NewAPIHandler.
	router := api.NewRouter(appConfig, proxyMgr)
	serverAddr := ":" + appConfig.Server.Port
	httpServer := &http.Server{
		Handler:      router, Addr: serverAddr,
		WriteTimeout: 30 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}

	log.Printf("Starting DomainFlow API server on http://localhost%s", serverAddr)
	if appConfig.Server.APIKey != "" && appConfig.Server.APIKey != config.DefaultSystemAPIKeyPlaceholder {
		log.Printf("API Key configured (length: %d). Ensure this is adequately secured.", len(appConfig.Server.APIKey))
	} else {
		log.Printf("API Key: Using default placeholder (length: %d). THIS IS INSECURE.", len(config.DefaultSystemAPIKeyPlaceholder))
	}

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server ListenAndServe failed: %v", err)
	}
}
