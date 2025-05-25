// File: backend/internal/api/handler_base.go
package api

import (
	"sync"

	"github.com/fntelecomllc/domainflow/backend/internal/campaigns"
	"github.com/fntelecomllc/domainflow/backend/internal/config"
	"github.com/fntelecomllc/domainflow/backend/internal/proxymanager"
)

// campaignDNSSettingsStore stores DNS settings per campaign.
// TODO: Consider moving this to a more persistent store or a dedicated service
// if campaign settings need to survive server restarts without explicit API calls.
// This will likely be superseded or integrated with the new CampaignStore.
var campaignDNSSettingsStore = make(map[string]*config.CampaignDNSSettings)
var campaignStoreMutex = &sync.RWMutex{}

// APIHandler holds shared dependencies for API handlers, like configuration and the proxy manager.
type APIHandler struct {
	Config        *config.AppConfig
	ProxyMgr      *proxymanager.ProxyManager
	CampaignMgr   campaigns.CampaignStore // Changed from CampaignStore to CampaignMgr as per convention
	configMutex   sync.RWMutex            // Protects AppConfig during dynamic updates (e.g., personas, server settings)
}

// NewAPIHandler creates a new APIHandler with dependencies.
func NewAPIHandler(cfg *config.AppConfig, pm *proxymanager.ProxyManager, campaignMgr campaigns.CampaignStore) *APIHandler {
	return &APIHandler{
		Config:      cfg,
		ProxyMgr:    pm,
		CampaignMgr: campaignMgr, // Changed from CampaignStore to CampaignMgr
	}
}
