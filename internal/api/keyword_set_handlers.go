// File: backend/internal/api/keyword_set_handlers.go
package api

import (
	"net/http"

	"github.com/fntelecomllc/domainflow/backend/internal/config"
)

// KeywordSetListItem defines the structure for listing keyword sets.
type KeywordSetListItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	RuleCount   int    `json:"ruleCount"`
}

// ListKeywordSetsHandler lists all available keyword sets.
func (h *APIHandler) ListKeywordSetsHandler(w http.ResponseWriter, r *http.Request) {
	h.configMutex.RLock()
	kkeywordSets := h.Config.KeywordSets
	h.configMutex.RUnlock()

	if kkeywordSets == nil {
		kkeywordSets = []config.KeywordSet{}
	}

	responseItems := make([]KeywordSetListItem, len(kkeywordSets))
	for i, ks := range kkeywordSets {
		responseItems[i] = KeywordSetListItem{
			ID:          ks.ID,
			Name:        ks.Name,
			Description: ks.Description,
			RuleCount:   len(ks.Rules),
		}
	}
	respondWithJSON(w, http.StatusOK, responseItems)
}
