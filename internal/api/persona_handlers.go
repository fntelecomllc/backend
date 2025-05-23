// File: backend/internal/api/persona_handlers.go
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/fntelecomllc/domainflow/backend/internal/config"
	"github.com/gorilla/mux"
)

// DNSPersonaListItem defines the structure for listing DNS personas.
type DNSPersonaListItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ListDNSPersonasHandler lists all available DNS personas.
func (h *APIHandler) ListDNSPersonasHandler(w http.ResponseWriter, r *http.Request) {
	h.configMutex.RLock()
	personas := h.Config.DNSPersonas
	h.configMutex.RUnlock()
	responseItems := make([]DNSPersonaListItem, len(personas))
	for i, p := range personas {
		responseItems[i] = DNSPersonaListItem{ID: p.ID, Name: p.Name, Description: p.Description}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(responseItems); err != nil {
		log.Printf("API Error: Encoding DNS Personas list: %v", err)
		// Consider using respondWithError if it doesn't cause import cycle with handler_utils
		// For now, using http.Error as it was in the original reverted code.
		http.Error(w, "Failed to encode DNS personas", http.StatusInternalServerError)
	}
}

// CreateDNSPersonaHandler creates a new DNS persona.
func (h *APIHandler) CreateDNSPersonaHandler(w http.ResponseWriter, r *http.Request) {
	var newPersona config.DNSPersona
	if err := json.NewDecoder(r.Body).Decode(&newPersona); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if newPersona.ID == "" {
		respondWithError(w, http.StatusBadRequest, "DNS Persona ID cannot be empty")
		return
	}

	h.configMutex.Lock()
	for _, p := range h.Config.DNSPersonas {
		if p.ID == newPersona.ID {
			h.configMutex.Unlock()
			respondWithError(w, http.StatusConflict, fmt.Sprintf("DNS persona with ID '%s' already exists", newPersona.ID))
			return
		}
	}

	h.Config.DNSPersonas = append(h.Config.DNSPersonas, newPersona)
	personasToSave := make([]config.DNSPersona, len(h.Config.DNSPersonas))
	copy(personasToSave, h.Config.DNSPersonas)
	configDir := filepath.Dir(h.Config.GetLoadedFromPath())
	if h.Config.GetLoadedFromPath() == "" || filepath.Base(h.Config.GetLoadedFromPath()) == h.Config.GetLoadedFromPath() {
		cwd, _ := os.Getwd()
		configDir = cwd
	}
	h.configMutex.Unlock()

	if err := config.SaveDNSPersonas(personasToSave, configDir); err != nil {
		log.Printf("Error saving DNS personas: %v", err)
		h.configMutex.Lock()
		for i, p := range h.Config.DNSPersonas {
			if p.ID == newPersona.ID {
				h.Config.DNSPersonas = append(h.Config.DNSPersonas[:i], h.Config.DNSPersonas[i+1:]...)
				break
			}
		}
		h.configMutex.Unlock()
		respondWithError(w, http.StatusInternalServerError, "Failed to save DNS persona")
		return
	}

	log.Printf("API: Created DNS Persona ID: %s, Name: %s", newPersona.ID, newPersona.Name)
	respondWithJSON(w, http.StatusCreated, newPersona)
}

// UpdateDNSPersonaHandler updates an existing DNS persona.
func (h *APIHandler) UpdateDNSPersonaHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	personaID := vars["personaId"]

	var updatedPersona config.DNSPersona
	if err := json.NewDecoder(r.Body).Decode(&updatedPersona); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if personaID != updatedPersona.ID {
		respondWithError(w, http.StatusBadRequest, "Persona ID in URL and payload must match")
		return
	}

	h.configMutex.Lock()
	found := false
	var originalPersona config.DNSPersona
	var personaIndex int

	for i, p := range h.Config.DNSPersonas {
		if p.ID == personaID {
			originalPersona = p
			h.Config.DNSPersonas[i] = updatedPersona
			personaIndex = i
			found = true
			break
		}
	}

	if !found {
		h.configMutex.Unlock()
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("DNS persona with ID '%s' not found", personaID))
		return
	}

	personasToSave := make([]config.DNSPersona, len(h.Config.DNSPersonas))
	copy(personasToSave, h.Config.DNSPersonas)
	configDir := filepath.Dir(h.Config.GetLoadedFromPath())
	if h.Config.GetLoadedFromPath() == "" || filepath.Base(h.Config.GetLoadedFromPath()) == h.Config.GetLoadedFromPath() {
		cwd, _ := os.Getwd()
		configDir = cwd
	}
	h.configMutex.Unlock()

	if err := config.SaveDNSPersonas(personasToSave, configDir); err != nil {
		log.Printf("Error saving DNS personas after update: %v", err)
		h.configMutex.Lock()
		if found {
			h.Config.DNSPersonas[personaIndex] = originalPersona
		}
		h.configMutex.Unlock()
		respondWithError(w, http.StatusInternalServerError, "Failed to update DNS persona")
		return
	}

	log.Printf("API: Updated DNS Persona ID: %s", updatedPersona.ID)
	respondWithJSON(w, http.StatusOK, updatedPersona)
}

// DeleteDNSPersonaHandler deletes a DNS persona.
func (h *APIHandler) DeleteDNSPersonaHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	personaID := vars["personaId"]

	h.configMutex.Lock()
	found := false
	var originalPersonas []config.DNSPersona
	var newPersonas []config.DNSPersona

	originalPersonas = make([]config.DNSPersona, len(h.Config.DNSPersonas))
	copy(originalPersonas, h.Config.DNSPersonas)

	for _, p := range h.Config.DNSPersonas {
		if p.ID == personaID {
			found = true
		} else {
			newPersonas = append(newPersonas, p)
		}
	}

	if !found {
		h.configMutex.Unlock()
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("DNS persona with ID '%s' not found", personaID))
		return
	}

	h.Config.DNSPersonas = newPersonas
	personasToSave := make([]config.DNSPersona, len(h.Config.DNSPersonas))
	copy(personasToSave, h.Config.DNSPersonas)
	configDir := filepath.Dir(h.Config.GetLoadedFromPath())
	if h.Config.GetLoadedFromPath() == "" || filepath.Base(h.Config.GetLoadedFromPath()) == h.Config.GetLoadedFromPath() {
		cwd, _ := os.Getwd()
		configDir = cwd
	}
	h.configMutex.Unlock()

	if err := config.SaveDNSPersonas(personasToSave, configDir); err != nil {
		log.Printf("Error saving DNS personas after deletion: %v", err)
		h.configMutex.Lock()
		h.Config.DNSPersonas = originalPersonas
		h.configMutex.Unlock()
		respondWithError(w, http.StatusInternalServerError, "Failed to delete DNS persona")
		return
	}

	log.Printf("API: Deleted DNS Persona ID: %s", personaID)
	respondWithJSON(w, http.StatusNoContent, nil)
}

// HTTPPersonaListItem defines the structure for listing HTTP personas.
type HTTPPersonaListItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	UserAgent   string `json:"userAgent"`
}

// ListHTTPPersonasHandler lists all available HTTP personas.
func (h *APIHandler) ListHTTPPersonasHandler(w http.ResponseWriter, r *http.Request) {
	h.configMutex.RLock()
	personas := h.Config.HTTPPersonas
	h.configMutex.RUnlock()
	responseItems := make([]HTTPPersonaListItem, len(personas))
	for i, p := range personas {
		responseItems[i] = HTTPPersonaListItem{ID: p.ID, Name: p.Name, Description: p.Description, UserAgent: p.UserAgent}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(responseItems); err != nil {
		log.Printf("API Error: Encoding HTTP Personas list: %v", err)
		// Consider using respondWithError
		http.Error(w, "Failed to encode HTTP personas", http.StatusInternalServerError)
	}
}

// CreateHTTPPersonaHandler creates a new HTTP persona.
func (h *APIHandler) CreateHTTPPersonaHandler(w http.ResponseWriter, r *http.Request) {
	var newPersona config.HTTPPersona
	if err := json.NewDecoder(r.Body).Decode(&newPersona); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if newPersona.ID == "" {
		respondWithError(w, http.StatusBadRequest, "HTTP Persona ID cannot be empty")
		return
	}

	h.configMutex.Lock()
	for _, p := range h.Config.HTTPPersonas {
		if p.ID == newPersona.ID {
			h.configMutex.Unlock()
			respondWithError(w, http.StatusConflict, fmt.Sprintf("HTTP persona with ID '%s' already exists", newPersona.ID))
			return
		}
	}

	h.Config.HTTPPersonas = append(h.Config.HTTPPersonas, newPersona)
	personasToSave := make([]config.HTTPPersona, len(h.Config.HTTPPersonas))
	copy(personasToSave, h.Config.HTTPPersonas)
	configDir := filepath.Dir(h.Config.GetLoadedFromPath())
	if h.Config.GetLoadedFromPath() == "" || filepath.Base(h.Config.GetLoadedFromPath()) == h.Config.GetLoadedFromPath() {
		cwd, _ := os.Getwd()
		configDir = cwd
	}
	h.configMutex.Unlock()

	if err := config.SaveHTTPPersonas(personasToSave, configDir); err != nil {
		log.Printf("Error saving HTTP personas: %v", err)
		h.configMutex.Lock()
		for i, p := range h.Config.HTTPPersonas {
			if p.ID == newPersona.ID {
				h.Config.HTTPPersonas = append(h.Config.HTTPPersonas[:i], h.Config.HTTPPersonas[i+1:]...)
				break
			}
		}
		h.configMutex.Unlock()
		respondWithError(w, http.StatusInternalServerError, "Failed to save HTTP persona")
		return
	}

	log.Printf("API: Created HTTP Persona ID: %s, Name: %s", newPersona.ID, newPersona.Name)
	respondWithJSON(w, http.StatusCreated, newPersona)
}

// UpdateHTTPPersonaHandler updates an existing HTTP persona.
func (h *APIHandler) UpdateHTTPPersonaHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	personaID := vars["personaId"]

	var updatedPersona config.HTTPPersona
	if err := json.NewDecoder(r.Body).Decode(&updatedPersona); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if personaID != updatedPersona.ID {
		respondWithError(w, http.StatusBadRequest, "Persona ID in URL and payload must match")
		return
	}

	h.configMutex.Lock()
	found := false
	var originalPersona config.HTTPPersona
	var personaIndex int

	for i, p := range h.Config.HTTPPersonas {
		if p.ID == personaID {
			originalPersona = p
			h.Config.HTTPPersonas[i] = updatedPersona
			personaIndex = i
			found = true
			break
		}
	}

	if !found {
		h.configMutex.Unlock()
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("HTTP persona with ID '%s' not found", personaID))
		return
	}

	personasToSave := make([]config.HTTPPersona, len(h.Config.HTTPPersonas))
	copy(personasToSave, h.Config.HTTPPersonas)
	configDir := filepath.Dir(h.Config.GetLoadedFromPath())
	if h.Config.GetLoadedFromPath() == "" || filepath.Base(h.Config.GetLoadedFromPath()) == h.Config.GetLoadedFromPath() {
		cwd, _ := os.Getwd()
		configDir = cwd
	}
	h.configMutex.Unlock()

	if err := config.SaveHTTPPersonas(personasToSave, configDir); err != nil {
		log.Printf("Error saving HTTP personas after update: %v", err)
		h.configMutex.Lock()
		if found {
			h.Config.HTTPPersonas[personaIndex] = originalPersona
		}
		h.configMutex.Unlock()
		respondWithError(w, http.StatusInternalServerError, "Failed to update HTTP persona")
		return
	}

	log.Printf("API: Updated HTTP Persona ID: %s", updatedPersona.ID)
	respondWithJSON(w, http.StatusOK, updatedPersona)
}

// DeleteHTTPPersonaHandler deletes an HTTP persona.
func (h *APIHandler) DeleteHTTPPersonaHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	personaID := vars["personaId"]

	h.configMutex.Lock()
	found := false
	var originalPersonas []config.HTTPPersona
	var newPersonas []config.HTTPPersona

	originalPersonas = make([]config.HTTPPersona, len(h.Config.HTTPPersonas))
	copy(originalPersonas, h.Config.HTTPPersonas)

	for _, p := range h.Config.HTTPPersonas {
		if p.ID == personaID {
			found = true
		} else {
			newPersonas = append(newPersonas, p)
		}
	}

	if !found {
		h.configMutex.Unlock()
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("HTTP persona with ID '%s' not found", personaID))
		return
	}

	h.Config.HTTPPersonas = newPersonas
	personasToSave := make([]config.HTTPPersona, len(h.Config.HTTPPersonas))
	copy(personasToSave, h.Config.HTTPPersonas)
	configDir := filepath.Dir(h.Config.GetLoadedFromPath())
	if h.Config.GetLoadedFromPath() == "" || filepath.Base(h.Config.GetLoadedFromPath()) == h.Config.GetLoadedFromPath() {
		cwd, _ := os.Getwd()
		configDir = cwd
	}
	h.configMutex.Unlock()

	if err := config.SaveHTTPPersonas(personasToSave, configDir); err != nil {
		log.Printf("Error saving HTTP personas after deletion: %v", err)
		h.configMutex.Lock()
		h.Config.HTTPPersonas = originalPersonas
		h.configMutex.Unlock()
		respondWithError(w, http.StatusInternalServerError, "Failed to delete HTTP persona")
		return
	}

	log.Printf("API: Deleted HTTP Persona ID: %s", personaID)
	respondWithJSON(w, http.StatusNoContent, nil)
}
