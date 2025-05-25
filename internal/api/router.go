// File: backend/internal/api/router.go
package api

import (
	"net/http"

	"github.com/fntelecomllc/domainflow/backend/internal/campaigns"
	"github.com/fntelecomllc/domainflow/backend/internal/config"
	"github.com/fntelecomllc/domainflow/backend/internal/proxymanager"
	"github.com/gorilla/mux"
)

func NewRouter(cfg *config.AppConfig, proxyMgr *proxymanager.ProxyManager, campaignMgr campaigns.CampaignStore) *mux.Router {
	router := mux.NewRouter()
	apiHandler := NewAPIHandler(cfg, proxyMgr, campaignMgr) // Updated to pass campaignMgr

	router.Use(LoggingMiddleware)
	router.Use(CORSMiddleware)

	router.HandleFunc("/ping", apiHandler.PingHandler).Methods(http.MethodGet, http.MethodOptions)

	apiV1 := router.PathPrefix("/api/v1").Subrouter()
	apiV1.Use(APIKeyAuthMiddleware(cfg.Server.APIKey))

	// DNS Personas
	apiV1.HandleFunc("/dns/personas", apiHandler.ListDNSPersonasHandler).Methods(http.MethodGet, http.MethodOptions)
	apiV1.HandleFunc("/dns/personas", apiHandler.CreateDNSPersonaHandler).Methods(http.MethodPost, http.MethodOptions)
	apiV1.HandleFunc("/dns/personas/{personaId}", apiHandler.UpdateDNSPersonaHandler).Methods(http.MethodPut, http.MethodOptions)
	apiV1.HandleFunc("/dns/personas/{personaId}", apiHandler.DeleteDNSPersonaHandler).Methods(http.MethodDelete, http.MethodOptions)
	// HTTP Personas
	apiV1.HandleFunc("/http/personas", apiHandler.ListHTTPPersonasHandler).Methods(http.MethodGet, http.MethodOptions)
	apiV1.HandleFunc("/http/personas", apiHandler.CreateHTTPPersonaHandler).Methods(http.MethodPost, http.MethodOptions)
	apiV1.HandleFunc("/http/personas/{personaId}", apiHandler.UpdateHTTPPersonaHandler).Methods(http.MethodPut, http.MethodOptions)
	apiV1.HandleFunc("/http/personas/{personaId}", apiHandler.DeleteHTTPPersonaHandler).Methods(http.MethodDelete, http.MethodOptions)

	// Proxy Management
	apiV1.HandleFunc("/proxies", apiHandler.ListProxiesHandler).Methods(http.MethodGet, http.MethodOptions)
	apiV1.HandleFunc("/proxies/status", apiHandler.GetProxyStatusesHandler).Methods(http.MethodGet, http.MethodOptions)
	apiV1.HandleFunc("/proxies", apiHandler.AddProxyHandler).Methods(http.MethodPost, http.MethodOptions)
	apiV1.HandleFunc("/proxies/{proxyId}", apiHandler.UpdateProxyHandler).Methods(http.MethodPut, http.MethodOptions)
	apiV1.HandleFunc("/proxies/{proxyId}", apiHandler.DeleteProxyHandler).Methods(http.MethodDelete, http.MethodOptions)
	apiV1.HandleFunc("/proxies/{proxyId}/test", apiHandler.TestProxyHandler).Methods(http.MethodPost, http.MethodOptions)
	apiV1.HandleFunc("/proxies/{proxyId}/health-check", apiHandler.ForceCheckSingleProxyHandler).Methods(http.MethodPost, http.MethodOptions)
	apiV1.HandleFunc("/proxies/health-check", apiHandler.ForceCheckAllProxiesHandler).Methods(http.MethodPost, http.MethodOptions)

	// Campaign DNS Settings (Legacy - to be reviewed/migrated to new campaign system)
	apiV1.HandleFunc("/campaigns/{campaignId}/dns/settings", apiHandler.GetCampaignDNSSettingsHandler).Methods(http.MethodGet, http.MethodOptions)
	apiV1.HandleFunc("/campaigns/{campaignId}/dns/settings", apiHandler.UpdateCampaignDNSSettingsHandler).Methods(http.MethodPut, http.MethodOptions)

	// DNS Validation
	apiV1.HandleFunc("/validate/dns", apiHandler.DNSValidateHandler).Methods(http.MethodPost, http.MethodOptions)
	apiV1.HandleFunc("/validate/dns/stream", apiHandler.DNSValidateStreamHandler).Methods(http.MethodGet, http.MethodOptions)

	// HTTP Validation
	apiV1.HandleFunc("/validate/http", apiHandler.HTTPValidateHandler).Methods(http.MethodPost, http.MethodOptions)
	apiV1.HandleFunc("/validate/http/stream", apiHandler.HTTPValidateStreamHandler).Methods(http.MethodGet, http.MethodOptions)

	// Configuration Management (Server Defaults)
	apiV1.HandleFunc("/config/dns", apiHandler.GetDNSConfigHandler).Methods(http.MethodGet, http.MethodOptions)
	apiV1.HandleFunc("/config/dns", apiHandler.UpdateDNSConfigHandler).Methods(http.MethodPost, http.MethodOptions)
	apiV1.HandleFunc("/config/http", apiHandler.GetHTTPConfigHandler).Methods(http.MethodGet, http.MethodOptions)
	apiV1.HandleFunc("/config/http", apiHandler.UpdateHTTPConfigHandler).Methods(http.MethodPost, http.MethodOptions)
	apiV1.HandleFunc("/config/logging", apiHandler.GetLoggingConfigHandler).Methods(http.MethodGet, http.MethodOptions)
	apiV1.HandleFunc("/config/logging", apiHandler.UpdateLoggingConfigHandler).Methods(http.MethodPost, http.MethodOptions)

	// NEW: Server-wide configuration (like StreamChunkSize)
	apiV1.HandleFunc("/config/server", apiHandler.GetServerConfigHandler).Methods(http.MethodGet, http.MethodOptions)
	apiV1.HandleFunc("/config/server", apiHandler.UpdateServerConfigHandler).Methods(http.MethodPut, http.MethodOptions)

	// Keyword Sets
	apiV1.HandleFunc("/keywords/sets", apiHandler.ListKeywordSetsHandler).Methods(http.MethodGet, http.MethodOptions)

	// Keyword Extraction
	apiV1.HandleFunc("/extract/keywords", apiHandler.BatchExtractKeywordsHandler).Methods(http.MethodPost, http.MethodOptions)
	apiV1.HandleFunc("/extract/keywords/stream", apiHandler.StreamExtractKeywordsHandler).Methods(http.MethodGet, http.MethodOptions)

	// New Campaign Routes (DNS Validation)
	apiV1.HandleFunc("/campaigns/dns", apiHandler.ListDNSCampaignsHandler).Methods(http.MethodGet, http.MethodOptions)
	apiV1.HandleFunc("/campaigns/dns", apiHandler.CreateDNSCampaignHandler).Methods(http.MethodPost, http.MethodOptions)
	apiV1.HandleFunc("/campaigns/dns/{campaignId}", apiHandler.GetDNSCampaignHandler).Methods(http.MethodGet, http.MethodOptions)
	apiV1.HandleFunc("/campaigns/dns/{campaignId}", apiHandler.UpdateDNSCampaignHandler).Methods(http.MethodPut, http.MethodOptions)
	apiV1.HandleFunc("/campaigns/dns/{campaignId}", apiHandler.DeleteDNSCampaignHandler).Methods(http.MethodDelete, http.MethodOptions)
	apiV1.HandleFunc("/campaigns/dns/{campaignId}/upload", apiHandler.UploadDNSCampaignDomainsHandler).Methods(http.MethodPost, http.MethodOptions)
	apiV1.HandleFunc("/campaigns/dns/{campaignId}/domains", apiHandler.GetDNSCampaignDomainsHandler).Methods(http.MethodGet, http.MethodOptions)
	apiV1.HandleFunc("/campaigns/dns/{campaignId}/results", apiHandler.GetDNSCampaignResultsHandler).Methods(http.MethodGet, http.MethodOptions)
	apiV1.HandleFunc("/campaigns/dns/{campaignId}/retry", apiHandler.RetryDNSCampaignHandler).Methods(http.MethodPost, http.MethodOptions) // Added Retry handler

	return router
}
