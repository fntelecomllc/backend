// File: backend/internal/api/proxy_handlers.go
package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fntelecomllc/domainflow/backend/internal/config"
	"github.com/fntelecomllc/domainflow/backend/internal/proxymanager"
	"github.com/gorilla/mux"
)

func (h *APIHandler) ListProxiesHandler(w http.ResponseWriter, r *http.Request) {
    h.configMutex.RLock()
    proxiesToReturn := make([]config.ProxyConfigEntry, len(h.Config.Proxies))
    copy(proxiesToReturn, h.Config.Proxies)
    h.configMutex.RUnlock()
    sort.Slice(proxiesToReturn, func(i, j int) bool {
        return proxiesToReturn[i].ID < proxiesToReturn[j].ID
    })
    respondWithJSON(w, http.StatusOK, proxiesToReturn)
}

func (h *APIHandler) GetProxyStatusesHandler(w http.ResponseWriter, r *http.Request) {
    if h.ProxyMgr == nil {
        log.Println("API Error: GetProxyStatusesHandler - ProxyManager not initialized.")
        respondWithError(w, http.StatusInternalServerError, "ProxyManager not available")
        return
    }
    statuses := h.ProxyMgr.GetAllProxyStatuses()
    sort.Slice(statuses, func(i, j int) bool {
        return statuses[i].ID < statuses[j].ID
    })
    respondWithJSON(w, http.StatusOK, statuses)
}

func (h *APIHandler) ForceCheckSingleProxyHandler(w http.ResponseWriter, r *http.Request) {
    if h.ProxyMgr == nil {
        log.Println("API Error: ForceCheckSingleProxyHandler - ProxyManager not initialized.")
        respondWithError(w, http.StatusInternalServerError, "ProxyManager not available")
        return
    }
    vars := mux.Vars(r)
    proxyID, ok := vars["proxyId"]
    if !ok {
        respondWithError(w, http.StatusBadRequest, "Proxy ID missing in path")
        return
    }
    log.Printf("API: Received request to force health check for proxy ID '%s'", proxyID)
    updatedStatus, err := h.ProxyMgr.ForceCheckSingleProxy(proxyID)
    if err != nil {
        log.Printf("API Error: ForceCheckSingleProxyHandler - Error checking proxy ID '%s': %v", proxyID, err)
        respondWithError(w, http.StatusNotFound, err.Error())
        return
    }
    respondWithJSON(w, http.StatusOK, updatedStatus)
}

func (h *APIHandler) ForceCheckAllProxiesHandler(w http.ResponseWriter, r *http.Request) {
    if h.ProxyMgr == nil {
        log.Println("API Error: ForceCheckAllProxiesHandler - ProxyManager not initialized.")
        respondWithError(w, http.StatusInternalServerError, "ProxyManager not available")
        return
    }
    var reqBody struct {
        IDs []string `json:"ids"`
    }
    if r.Body != nil && r.ContentLength > 0 {
        bodyBytes, err := ioutil.ReadAll(r.Body)
        if err == nil && len(bodyBytes) > 0 {
            if errUnmarshal := json.Unmarshal(bodyBytes, &reqBody); errUnmarshal != nil {
                log.Printf("API Error: ForceCheckAllProxiesHandler - Invalid JSON in request body: %v", errUnmarshal)
                respondWithError(w, http.StatusBadRequest, "Invalid JSON in request body: "+errUnmarshal.Error())
                return
            }
        } else if err != nil {
            log.Printf("API Error: ForceCheckAllProxiesHandler - Failed to read request body: %v", err)
            respondWithError(w, http.StatusInternalServerError, "Failed to read request body: "+err.Error())
            return
        }
        defer r.Body.Close()
    }
    var message string
    if len(reqBody.IDs) > 0 {
        log.Printf("API: Received request to force health check for %d specific proxy IDs.", len(reqBody.IDs))
        h.ProxyMgr.ForceCheckProxiesAsync(reqBody.IDs)
        message = fmt.Sprintf("Health check process initiated for %d specified proxies. Check /api/v1/proxies/status for updates.", len(reqBody.IDs))
    } else {
        log.Printf("API: Received request to force health check for ALL managed proxies.")
        h.ProxyMgr.ForceCheckProxiesAsync(nil)
        message = "Health check process initiated for all managed proxies. Check /api/v1/proxies/status for updates."
    }
    respondWithJSON(w, http.StatusAccepted, map[string]string{"message": message})
}

func (h *APIHandler) AddProxyHandler(w http.ResponseWriter, r *http.Request) {
    var newProxy config.ProxyConfigEntry
    if err := json.NewDecoder(r.Body).Decode(&newProxy); err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
        return
    }
    defer r.Body.Close()
    if newProxy.ID == "" || newProxy.Protocol == "" || newProxy.Address == "" {
        respondWithError(w, http.StatusBadRequest, "Proxy ID, Protocol, and Address are required")
        return
    }
    validProtocols := map[string]bool{"http": true, "https": true}
    if !validProtocols[strings.ToLower(newProxy.Protocol)] {
        respondWithError(w, http.StatusBadRequest, "Invalid proxy protocol. Supported: http, https")
        return
    }
    h.configMutex.Lock()
    defer h.configMutex.Unlock()
    for _, p := range h.Config.Proxies {
        if p.ID == newProxy.ID {
            respondWithError(w, http.StatusConflict, fmt.Sprintf("Proxy ID '%s' already exists", newProxy.ID))
            return
        }
    }
    h.Config.Proxies = append(h.Config.Proxies, newProxy)
    configDir := filepath.Dir(h.Config.GetLoadedFromPath())
    if h.Config.GetLoadedFromPath() == "" || filepath.Base(h.Config.GetLoadedFromPath()) == h.Config.GetLoadedFromPath() {
        cwd, _ := os.Getwd()
        configDir = cwd
    }
    if err := config.SaveProxies(h.Config.Proxies, configDir); err != nil {
        log.Printf("API Error: Failed to save proxies: %v.", err)
        // Not returning error to client as proxy was added in memory, but save failed.
    }
    log.Printf("API: Added new proxy: ID='%s'", newProxy.ID)
    respondWithJSON(w, http.StatusCreated, newProxy)
}

func (h *APIHandler) UpdateProxyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	proxyID, ok := vars["proxyId"]
	if !ok {
		respondWithError(w, http.StatusBadRequest, "Proxy ID missing")
		return
	}

	var reqUpdate struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Protocol    *string `json:"protocol"`
		Address     *string `json:"address"`
		Username    *string `json:"username"`
		Password    *string `json:"password"`
		Notes       *string `json:"notes"`
		UserEnabled *bool   `json:"userEnabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqUpdate); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}
	defer r.Body.Close()

	if reqUpdate.Protocol != nil && *reqUpdate.Protocol != "" {
		validProtocols := map[string]bool{"http": true, "https": true}
		if !validProtocols[strings.ToLower(*reqUpdate.Protocol)] {
			respondWithError(w, http.StatusBadRequest, "Invalid proxy protocol. Supported: http, https")
			return
		}
	}

	h.configMutex.Lock()
	defer h.configMutex.Unlock()

	foundIndex := -1
	for i, p := range h.Config.Proxies {
		if p.ID == proxyID {
			foundIndex = i
			break
		}
	}

	if foundIndex == -1 {
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("Proxy ID '%s' not found", proxyID))
		return
	}

	configActuallyChanged := false
	if reqUpdate.Name != nil {
		if h.Config.Proxies[foundIndex].Name != *reqUpdate.Name {
			h.Config.Proxies[foundIndex].Name = *reqUpdate.Name
			configActuallyChanged = true
		}
	}
	if reqUpdate.Description != nil {
		if h.Config.Proxies[foundIndex].Description != *reqUpdate.Description {
			h.Config.Proxies[foundIndex].Description = *reqUpdate.Description
			configActuallyChanged = true
		}
	}
	if reqUpdate.Protocol != nil && *reqUpdate.Protocol != "" {
		if h.Config.Proxies[foundIndex].Protocol != *reqUpdate.Protocol {
			h.Config.Proxies[foundIndex].Protocol = *reqUpdate.Protocol
			configActuallyChanged = true
		}
	}
	if reqUpdate.Address != nil && *reqUpdate.Address != "" {
		if h.Config.Proxies[foundIndex].Address != *reqUpdate.Address {
			h.Config.Proxies[foundIndex].Address = *reqUpdate.Address
			configActuallyChanged = true
		}
	}
	if reqUpdate.Username != nil {
		if h.Config.Proxies[foundIndex].Username != *reqUpdate.Username {
			h.Config.Proxies[foundIndex].Username = *reqUpdate.Username
			configActuallyChanged = true
		}
	}
	if reqUpdate.Password != nil {
		if h.Config.Proxies[foundIndex].Password != *reqUpdate.Password {
			h.Config.Proxies[foundIndex].Password = *reqUpdate.Password
			configActuallyChanged = true
		}
	}
	if reqUpdate.Notes != nil {
		if h.Config.Proxies[foundIndex].Notes != *reqUpdate.Notes {
			h.Config.Proxies[foundIndex].Notes = *reqUpdate.Notes
			configActuallyChanged = true
		}
	}
	if reqUpdate.UserEnabled != nil {
		if h.Config.Proxies[foundIndex].UserEnabled == nil || *h.Config.Proxies[foundIndex].UserEnabled != *reqUpdate.UserEnabled {
			h.Config.Proxies[foundIndex].UserEnabled = reqUpdate.UserEnabled
			configActuallyChanged = true
			log.Printf("API: UserEnabled for proxy ID '%s' set to %t in config.", proxyID, *reqUpdate.UserEnabled)
			if h.ProxyMgr != nil {
				err := h.ProxyMgr.UpdateProxyUserEnabledStatus(proxyID, *reqUpdate.UserEnabled)
				if err != nil {
					log.Printf("API Warning: Failed to update ProxyManager state for UserEnabled on proxy ID '%s': %v", proxyID, err)
				}
			}
		}
	}

	if configActuallyChanged {
		configDir := filepath.Dir(h.Config.GetLoadedFromPath())
		if h.Config.GetLoadedFromPath() == "" || filepath.Base(h.Config.GetLoadedFromPath()) == h.Config.GetLoadedFromPath() {
			cwd, _ := os.Getwd()
			configDir = cwd
		}
		if err := config.SaveProxies(h.Config.Proxies, configDir); err != nil {
			log.Printf("API Error: UpdateProxyHandler - Failed to save proxies: %v.", err)
		}
		log.Printf("API: Updated proxy details for ID='%s' and saved to proxies.config.json", proxyID)
	} else {
		log.Printf("API: No changes detected for proxy ID='%s'. No save needed.", proxyID)
	}

	respondWithJSON(w, http.StatusOK, h.Config.Proxies[foundIndex])
}

func (h *APIHandler) DeleteProxyHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    proxyID, ok := vars["proxyId"]
    if !ok {
        respondWithError(w, http.StatusBadRequest, "Proxy ID missing")
        return
    }
    h.configMutex.Lock()
    defer h.configMutex.Unlock()
    foundIndex := -1
    for i, p := range h.Config.Proxies {
        if p.ID == proxyID {
            foundIndex = i
            break
        }
    }
    if foundIndex != -1 {
        h.Config.Proxies = append(h.Config.Proxies[:foundIndex], h.Config.Proxies[foundIndex+1:]...)
        configDir := filepath.Dir(h.Config.GetLoadedFromPath())
        if h.Config.GetLoadedFromPath() == "" || filepath.Base(h.Config.GetLoadedFromPath()) == h.Config.GetLoadedFromPath() {
            cwd, _ := os.Getwd()
            configDir = cwd
        }
        if err := config.SaveProxies(h.Config.Proxies, configDir); err != nil {
            log.Printf("API Error: Failed to save proxies after deletion: %v.", err)
        }
        log.Printf("API: Deleted proxy: ID='%s'", proxyID)
        respondWithJSON(w, http.StatusNoContent, nil) // Use respondWithJSON for consistency
        return
    }
    respondWithError(w, http.StatusNotFound, fmt.Sprintf("Proxy ID '%s' not found", proxyID))
}

func (h *APIHandler) TestProxyHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    proxyID, ok := vars["proxyId"]
    if !ok {
        respondWithError(w, http.StatusBadRequest, "Proxy ID missing")
        return
    }
    h.configMutex.RLock()
    var targetProxy *config.ProxyConfigEntry
    for _, p := range h.Config.Proxies {
        if p.ID == proxyID {
            pCopy := p 
            targetProxy = &pCopy
            break
        }
    }
    h.configMutex.RUnlock()
    if targetProxy == nil {
        respondWithError(w, http.StatusNotFound, fmt.Sprintf("Proxy ID '%s' not found for testing", proxyID))
        return
    }
    lcProtocol := strings.ToLower(targetProxy.Protocol)
    if lcProtocol != "http" && lcProtocol != "https" {
        errorMsg := fmt.Sprintf("Proxy ID '%s' has unsupported protocol '%s' for testing. Supported: http, https.", targetProxy.ID, targetProxy.Protocol)
        log.Printf("API: %s", errorMsg)
        testResult := proxymanager.ProxyTestResult{
            ProxyID:    targetProxy.ID,
            Success:    false,
            Error:      errorMsg,
            DurationMs: 0,
        }
        respondWithJSON(w, http.StatusBadRequest, testResult)
        return
    }
    log.Printf("API: Testing proxy ID '%s' (%s://%s)", targetProxy.ID, targetProxy.Protocol, targetProxy.Address)
    testResult := proxymanager.TestProxy(*targetProxy)
    respondWithJSON(w, http.StatusOK, testResult)
}
