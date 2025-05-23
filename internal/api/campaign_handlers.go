// File: backend/internal/api/campaign_handlers.go
package api
                              
import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/fntelecomllc/domainflow/backend/internal/config"
	"github.com/gorilla/mux"
)

// UpdateCampaignDNSSettingsRequest defines the structure for updating campaign DNS settings.
type UpdateCampaignDNSSettingsRequest struct {
	RotationMode       config.CampaignDNSRotationMode `json:"rotationMode"`
	SelectedPersonaIDs []string                       `json:"selectedPersonaIds,omitempty"`
}

// GetCampaignDNSSettingsHandler retrieves DNS settings for a specific campaign.
func (h *APIHandler) GetCampaignDNSSettingsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	campaignID, ok := vars["campaignId"]
	if !ok {
		respondWithError(w, http.StatusBadRequest, "Campaign ID missing")
		return
	}
	campaignStoreMutex.RLock() // Uses global mutex for campaignDNSSettingsStore
	settings, exists := campaignDNSSettingsStore[campaignID]
	campaignStoreMutex.RUnlock()
	if !exists {
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("DNS settings not found for campaign: %s", campaignID))
		return
	}
	respondWithJSON(w, http.StatusOK, settings)
}

// UpdateCampaignDNSSettingsHandler creates or updates the DNS validation settings for a specific campaign.
func (h *APIHandler) UpdateCampaignDNSSettingsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	campaignID, ok := vars["campaignId"]
	if !ok {
		respondWithError(w, http.StatusBadRequest, "Campaign ID missing")
		return
	}
	var req UpdateCampaignDNSSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}
	defer r.Body.Close()
	validModes := map[config.CampaignDNSRotationMode]bool{
		config.RotationAllSequential:         true,
		config.RotationAllRandomPerDomain:    true,
		config.RotationAllRandomPerRequest:   true,
		config.RotationManualSequential:      true,
		config.RotationManualRandomPerDomain: true,
		config.RotationManualRandomPerRequest: true,
	}
	if !validModes[req.RotationMode] {
		respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Invalid rotationMode: '%s'", req.RotationMode))
		return
	}
	isManualMode := strings.HasPrefix(string(req.RotationMode), "manual_")
	if isManualMode && (req.SelectedPersonaIDs == nil || len(req.SelectedPersonaIDs) == 0) {
		respondWithError(w, http.StatusBadRequest, "selectedPersonaIds must be non-empty for manual modes")
		return
	}
	if isManualMode {
		h.configMutex.RLock()
		loadedPersonas := h.Config.DNSPersonas
		h.configMutex.RUnlock()
		validPIDs := make(map[string]bool)
		for _, p := range loadedPersonas {
			validPIDs[p.ID] = true
		}
		for _, sID := range req.SelectedPersonaIDs {
			if !validPIDs[sID] {
				respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Invalid persona ID '%s'", sID))
				return
			}
		}
	}
	newSettings := &config.CampaignDNSSettings{
		CampaignID:         campaignID,
		RotationMode:       req.RotationMode,
		SelectedPersonaIDs: req.SelectedPersonaIDs,
	}
	campaignStoreMutex.Lock() // Uses global mutex
	campaignDNSSettingsStore[campaignID] = newSettings
	campaignStoreMutex.Unlock()
	log.Printf("API: Updated DNS settings for campaign '%s': Mode='%s', Personas=%v", campaignID, newSettings.RotationMode, newSettings.SelectedPersonaIDs)
	respondWithJSON(w, http.StatusOK, newSettings)
}
