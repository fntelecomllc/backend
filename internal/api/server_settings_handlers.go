// File: backend/internal/api/server_settings_handlers.go
package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/fntelecomllc/domainflow/backend/internal/config"
)

// GetServerConfigHandler retrieves current server-wide configurations like port and streamChunkSize.
func (h *APIHandler) GetServerConfigHandler(w http.ResponseWriter, r *http.Request) {
    h.configMutex.RLock()
    serverConfigDTO := struct {
        Port            string `json:"port"`
        StreamChunkSize int    `json:"streamChunkSize"`
    }{
        Port:            h.Config.Server.Port,
        StreamChunkSize: h.Config.Server.StreamChunkSize,
    }
    h.configMutex.RUnlock()
    respondWithJSON(w, http.StatusOK, serverConfigDTO)
}

// UpdateServerConfigHandler updates server-wide configurations like streamChunkSize.
func (h *APIHandler) UpdateServerConfigHandler(w http.ResponseWriter, r *http.Request) {
    var reqServerConfigUpdate struct {
        StreamChunkSize *int `json:"streamChunkSize"`
    }
    if err := json.NewDecoder(r.Body).Decode(&reqServerConfigUpdate); err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
        return
    }
    defer r.Body.Close()
    configChanged := false
    h.configMutex.Lock()
    if reqServerConfigUpdate.StreamChunkSize != nil {
        if *reqServerConfigUpdate.StreamChunkSize > 0 {
            if h.Config.Server.StreamChunkSize != *reqServerConfigUpdate.StreamChunkSize {
                h.Config.Server.StreamChunkSize = *reqServerConfigUpdate.StreamChunkSize
                configChanged = true
                log.Printf("API: Server StreamChunkSize updated to: %d", h.Config.Server.StreamChunkSize)
            }
        } else {
            log.Printf("API Warning: UpdateServerConfigHandler - Invalid StreamChunkSize received: %d. Value must be > 0. Not updating.", *reqServerConfigUpdate.StreamChunkSize)
        }
    }
    if configChanged {
        // Save the entire AppConfig; h.Config already holds the updated Server part.
        if err := config.Save(h.Config, h.Config.GetLoadedFromPath()); err != nil {
            h.configMutex.Unlock()
            log.Printf("API Error: UpdateServerConfigHandler - Failed to save updated server config: %v", err)
            respondWithError(w, http.StatusInternalServerError, "Failed to save server configuration")
            return
        }
    }
    h.configMutex.Unlock()
    currentServerConfigDTO := struct {
        Port            string `json:"port"`
        StreamChunkSize int    `json:"streamChunkSize"`
    }{
        Port:            h.Config.Server.Port,
        StreamChunkSize: h.Config.Server.StreamChunkSize,
    }
    respondWithJSON(w, http.StatusOK, currentServerConfigDTO)
}

// GetDNSConfigHandler retrieves the default DNS validator configuration.
func (h *APIHandler) GetDNSConfigHandler(w http.ResponseWriter, r *http.Request) {
    h.configMutex.RLock()
    dnsConfigJSON := config.ConvertDNSConfigToJSON(h.Config.DNSValidator)
    h.configMutex.RUnlock()
    respondWithJSON(w, http.StatusOK, dnsConfigJSON)
}

// UpdateDNSConfigHandler updates the default DNS validator configuration.
func (h *APIHandler) UpdateDNSConfigHandler(w http.ResponseWriter, r *http.Request) {
    var reqJSON config.DNSValidatorConfigJSON
    if err := json.NewDecoder(r.Body).Decode(&reqJSON); err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
        return
    }
    defer r.Body.Close()
    updatedDNSConfig := config.ConvertJSONToDNSConfig(reqJSON)
    h.configMutex.Lock()
    h.Config.DNSValidator = updatedDNSConfig
    configToSave := *h.Config 
    h.configMutex.Unlock()
    if err := config.Save(&configToSave, configToSave.GetLoadedFromPath()); err != nil {
        log.Printf("API Error: Failed to save updated DNS config: %v", err)
        respondWithError(w, http.StatusInternalServerError, "Failed to save DNS configuration")
        return
    }
    log.Printf("API: Updated server default DNS configuration.")
    respondWithJSON(w, http.StatusOK, reqJSON)
}

// GetHTTPConfigHandler retrieves the default HTTP validator configuration.
func (h *APIHandler) GetHTTPConfigHandler(w http.ResponseWriter, r *http.Request) {
    h.configMutex.RLock()
    httpConfigJSON := config.ConvertHTTPConfigToJSON(h.Config.HTTPValidator)
    h.configMutex.RUnlock()
    respondWithJSON(w, http.StatusOK, httpConfigJSON)
}

// UpdateHTTPConfigHandler updates the default HTTP validator configuration.
func (h *APIHandler) UpdateHTTPConfigHandler(w http.ResponseWriter, r *http.Request) {
    var reqJSON config.HTTPValidatorConfigJSON
    if err := json.NewDecoder(r.Body).Decode(&reqJSON); err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
        return
    }
    defer r.Body.Close()
    updatedHTTPConfig := config.ConvertJSONToHTTPConfig(reqJSON)
    h.configMutex.Lock()
    h.Config.HTTPValidator = updatedHTTPConfig
    configToSave := *h.Config 
    h.configMutex.Unlock()
    if err := config.Save(&configToSave, configToSave.GetLoadedFromPath()); err != nil {
        log.Printf("API Error: Failed to save updated HTTP config: %v", err)
        respondWithError(w, http.StatusInternalServerError, "Failed to save HTTP configuration")
        return
    }
    log.Printf("API: Updated server default HTTP configuration.")
    respondWithJSON(w, http.StatusOK, reqJSON)
}

// GetLoggingConfigHandler retrieves the current logging configuration.
func (h *APIHandler) GetLoggingConfigHandler(w http.ResponseWriter, r *http.Request) {
    h.configMutex.RLock()
    loggingConfig := h.Config.Logging
    h.configMutex.RUnlock()
    respondWithJSON(w, http.StatusOK, loggingConfig)
}

// UpdateLoggingConfigHandler updates the logging configuration.
func (h *APIHandler) UpdateLoggingConfigHandler(w http.ResponseWriter, r *http.Request) {
    var reqLogging config.LoggingConfig
    if err := json.NewDecoder(r.Body).Decode(&reqLogging); err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
        return
    }
    defer r.Body.Close()
    h.configMutex.Lock()
    h.Config.Logging = reqLogging
    configToSave := *h.Config 
    h.configMutex.Unlock()
    if err := config.Save(&configToSave, configToSave.GetLoadedFromPath()); err != nil {
        log.Printf("API Error: Failed to save updated Logging config: %v", err)
        respondWithError(w, http.StatusInternalServerError, "Failed to save Logging configuration")
        return
    }
    log.Printf("API: Updated server Logging configuration. New level: %s", reqLogging.Level)
    respondWithJSON(w, http.StatusOK, reqLogging)
}
