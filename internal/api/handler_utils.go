// File: backend/internal/api/handler_utils.go
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/fntelecomllc/domainflow/backend/internal/config"
)

// respondWithError sends a JSON error response.
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

// respondWithJSON sends a JSON response with the given status code and payload.
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		log.Printf("API Error: Failed to marshal JSON response: %v", err)
		// Fallback error response if marshalling the payload fails
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		jsonError := fmt.Sprintf("{\"error\": \"Failed to marshal JSON response: %v\"}", err)
		w.Write([]byte(jsonError))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if payload != nil { // Avoid writing null body if payload is nil (e.g. for 204 No Content)
		w.Write(response)
	}
}

// getProxyLogStr formats a proxy entry for logging.
func getProxyLogStr(p *config.ProxyConfigEntry) string {
	if p == nil {
		return "<none>"
	}
	return fmt.Sprintf("ID %s (%s://%s)", p.ID, p.Protocol, p.Address)
}
