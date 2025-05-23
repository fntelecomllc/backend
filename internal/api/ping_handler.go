// File: backend/internal/api/ping_handler.go
package api

import (
	"encoding/json"
	"net/http"
	"time"
)

// PingHandler responds to ping requests to check server health.
func (h *APIHandler) PingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "pong", "timestamp": time.Now().Format(time.RFC3339)})
}
