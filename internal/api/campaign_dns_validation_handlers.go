// File: backend/internal/api/campaign_dns_validation_handlers.go
package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/fntelecomllc/domainflow/backend/internal/campaigns"
	"github.com/fntelecomllc/domainflow/backend/internal/campaigns/dnsvalidation"
	"github.com/fntelecomllc/domainflow/backend/internal/dnsvalidator" // Added for RetryDNSCampaignHandler
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// dnsCampaignApiType defines the type string for DNS campaigns for consistency within this package.
const dnsCampaignApiType = "DNS_VALIDATION"
const maxUploadSize = 5 * 1024 * 1024 // 5 MB

// --- DTOs ---

// CreateDNSCampaignRequest defines the expected payload for creating a DNS campaign.
type CreateDNSCampaignRequest struct {
	CampaignName  string   `json:"campaignName"`
	Description   string   `json:"description,omitempty"`
	DNSPersonaIDs []string `json:"dnsPersonaIds"` // Multi-persona support
	Notes         string   `json:"notes,omitempty"`
	Tags          []string `json:"tags,omitempty"`
}

// UpdateDNSCampaignRequest defines the expected payload for updating a DNS campaign.
// Only includes fields that are allowed to be updated.
type UpdateDNSCampaignRequest struct {
	CampaignName  *string   `json:"campaignName,omitempty"`  // Pointer to distinguish between empty and not provided
	Description   *string   `json:"description,omitempty"`
	DNSPersonaIDs *[]string `json:"dnsPersonaIds,omitempty"` // Pointer to slice for multi-persona
	Notes         *string   `json:"notes,omitempty"`
	Tags          []string  `json:"tags,omitempty"`        // For tags, empty list means clear, null/omitted means no change.
	Status        *string   `json:"status,omitempty"`      // Allow status updates, e.g., to pause/resume
}

// --- Handlers ---

// CreateDNSCampaignHandler handles the creation of new DNS validation campaigns.
// POST /api/v1/campaigns/dns
func (h *APIHandler) CreateDNSCampaignHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateDNSCampaignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload: "+err.Error())
		return
	}

	if req.CampaignName == "" {
		respondWithError(w, http.StatusBadRequest, "Campaign name is required")
		return
	}
	if len(req.DNSPersonaIDs) == 0 { // Validation for non-empty DNSPersonaIDs
		respondWithError(w, http.StatusBadRequest, "At least one DNS Persona ID is required")
		return
	}
	// TODO: Optionally, validate if persona IDs actually exist in the system.

	now := time.Now().UTC()
	newCampaignID := uuid.NewString()

	campaign := &dnsvalidation.DNSValidationCampaign{
		BaseCampaign: campaigns.BaseCampaign{
			CampaignID:   newCampaignID,
			CampaignName: req.CampaignName,
			Description:  req.Description,
			CampaignType: dnsCampaignApiType,
			Status:       campaigns.StatusPending,
			CreatedAt:    now,
			UpdatedAt:    now,
			Notes:        req.Notes,
			Tags:         req.Tags,
			AuditLog:     make([]campaigns.CampaignAuditEntry, 0),
		},
		DNSPersonaIDs: req.DNSPersonaIDs, // Use the list of IDs
		UploadHistory: make([]campaigns.UploadEvent, 0),
		// InitialNumberOfDomains and ProcessedDomainsCount default to 0
	}

	if err := h.CampaignMgr.CreateCampaign(campaign); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create campaign: "+err.Error())
		return
	}

	auditEntry := campaigns.CampaignAuditEntry{
		Timestamp:   now,
		Action:      "Campaign Created",
		Description: fmt.Sprintf("Campaign '%s' created with ID %s using DNS personas: %v", campaign.CampaignName, campaign.CampaignID, campaign.DNSPersonaIDs),
	}
	if err := h.CampaignMgr.LogAuditEvent(campaign.CampaignID, dnsCampaignApiType, auditEntry); err != nil {
		log.Printf("Error logging audit event for campaign %s: %v", campaign.CampaignID, err)
	}

	respondWithJSON(w, http.StatusCreated, campaign)
}

// GetDNSCampaignHandler handles fetching a specific DNS validation campaign.
// GET /api/v1/campaigns/dns/{campaignId}
func (h *APIHandler) GetDNSCampaignHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	campaignID, ok := vars["campaignId"]
	if !ok {
		respondWithError(w, http.StatusBadRequest, "Campaign ID is missing in URL path")
		return
	}

	campaignData, err := h.CampaignMgr.GetCampaign(campaignID, dnsCampaignApiType)
	if err != nil {
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("Campaign with ID %s not found", campaignID))
		return
	}

	dnsCampaign, ok := campaignData.(*dnsvalidation.DNSValidationCampaign)
	if !ok {
		respondWithError(w, http.StatusInternalServerError, "Failed to assert campaign data type after retrieval")
		return
	}

	respondWithJSON(w, http.StatusOK, dnsCampaign)
}

// ListDNSCampaignsHandler handles listing all DNS validation campaigns.
// GET /api/v1/campaigns/dns
func (h *APIHandler) ListDNSCampaignsHandler(w http.ResponseWriter, r *http.Request) {
	filters := make(map[string]string)
	statusQuery := r.URL.Query().Get("status")
	if statusQuery != "" {
		filters["status"] = statusQuery
	}

	var paginationOpts interface{} = nil

	campaignsList, err := h.CampaignMgr.ListCampaigns(dnsCampaignApiType, filters, paginationOpts)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to list campaigns: "+err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, campaignsList)
}

// UpdateDNSCampaignHandler handles updating an existing DNS validation campaign.
// PUT /api/v1/campaigns/dns/{campaignId}
func (h *APIHandler) UpdateDNSCampaignHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	campaignID, ok := vars["campaignId"]
	if !ok {
		respondWithError(w, http.StatusBadRequest, "Campaign ID is missing in URL path")
		return
	}

	var req UpdateDNSCampaignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload: "+err.Error())
		return
	}

	campaignData, err := h.CampaignMgr.GetCampaign(campaignID, dnsCampaignApiType)
	if err != nil {
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("Campaign with ID %s not found", campaignID))
		return
	}

	existingCampaign, ok := campaignData.(*dnsvalidation.DNSValidationCampaign)
	if !ok {
		respondWithError(w, http.StatusInternalServerError, "Failed to assert campaign data type for update")
		return
	}

	updatedFields := false
	if req.CampaignName != nil {
		if *req.CampaignName == "" {
			respondWithError(w, http.StatusBadRequest, "Campaign name cannot be empty if provided for update")
			return
		}
		existingCampaign.CampaignName = *req.CampaignName
		updatedFields = true
	}
	if req.Description != nil {
		existingCampaign.Description = *req.Description
		updatedFields = true
	}
	if req.DNSPersonaIDs != nil { // If DNSPersonaIDs field is present in the request
		if len(*req.DNSPersonaIDs) == 0 { // Check if the provided list is empty
			respondWithError(w, http.StatusBadRequest, "DNS Persona IDs list cannot be empty if provided for update.")
			return
		}
		// TODO: Optionally, validate if persona IDs actually exist.
		existingCampaign.DNSPersonaIDs = *req.DNSPersonaIDs
		updatedFields = true
	}
	if req.Notes != nil {
		existingCampaign.Notes = *req.Notes
		updatedFields = true
	}
	if req.Tags != nil {
		existingCampaign.Tags = req.Tags
		updatedFields = true
	}
	if req.Status != nil {
		newStatus := campaigns.CampaignStatus(*req.Status)
		switch newStatus {
		case campaigns.StatusPending, campaigns.StatusActive, campaigns.StatusPaused, campaigns.StatusCompleted, campaigns.StatusFailed, campaigns.StatusCancelled, campaigns.StatusError, campaigns.StatusRetrying:
			existingCampaign.Status = newStatus
			updatedFields = true
		default:
			respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Invalid status value: %s", *req.Status))
			return
		}
	}

	if !updatedFields {
		respondWithJSON(w, http.StatusOK, existingCampaign)
		return
	}

	existingCampaign.UpdatedAt = time.Now().UTC()

	if err := h.CampaignMgr.UpdateCampaign(existingCampaign); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to update campaign: "+err.Error())
		return
	}

	auditEntry := campaigns.CampaignAuditEntry{
		Timestamp:   existingCampaign.UpdatedAt,
		Action:      "Campaign Updated",
		Description: fmt.Sprintf("Campaign '%s' (ID %s) was updated. DNS Personas: %v", existingCampaign.CampaignName, existingCampaign.CampaignID, existingCampaign.DNSPersonaIDs),
	}
	if err := h.CampaignMgr.LogAuditEvent(existingCampaign.CampaignID, dnsCampaignApiType, auditEntry); err != nil {
		log.Printf("Error logging audit event for campaign update %s: %v", existingCampaign.CampaignID, err)
	}

	respondWithJSON(w, http.StatusOK, existingCampaign)
}

// DeleteDNSCampaignHandler handles deleting a specific DNS validation campaign.
// DELETE /api/v1/campaigns/dns/{campaignId}
func (h *APIHandler) DeleteDNSCampaignHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("DEBUG: DeleteDNSCampaignHandler invoked for request: %s %s", r.Method, r.URL.Path)
	vars := mux.Vars(r)
	campaignID, ok := vars["campaignId"]
	if !ok {
		log.Printf("DEBUG: Campaign ID missing in URL path for DeleteDNSCampaignHandler")
		respondWithError(w, http.StatusBadRequest, "Campaign ID is missing in URL path")
		return
	}
	log.Printf("DEBUG: Attempting to delete campaign with ID: %s", campaignID)

	campaignData, err := h.CampaignMgr.GetCampaign(campaignID, dnsCampaignApiType)
	if err != nil {
		log.Printf("DEBUG: Campaign with ID %s not found for deletion (GetCampaign error: %v)", campaignID, err)
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("Campaign with ID %s not found", campaignID))
		return
	}
	log.Printf("DEBUG: Campaign with ID %s found, proceeding with deletion.", campaignID)
	
	existingCampaignForAudit, ok := campaignData.(*dnsvalidation.DNSValidationCampaign)
	if !ok {
		log.Printf("ERROR: Retrieved campaign data for ID %s is of unexpected type before deletion", campaignID)
		respondWithError(w, http.StatusInternalServerError, "Retrieved campaign data is of unexpected type")
		return
	}

	if err := h.CampaignMgr.DeleteCampaign(campaignID, dnsCampaignApiType); err != nil {
		log.Printf("ERROR: Failed to delete campaign %s from store: %v", campaignID, err)
		respondWithError(w, http.StatusInternalServerError, "Failed to delete campaign: "+err.Error())
		return
	}
	log.Printf("DEBUG: Campaign %s successfully deleted from store.", campaignID)

	auditEntry := campaigns.CampaignAuditEntry{
		Timestamp:   time.Now().UTC(),
		Action:      "Campaign Deleted",
		Description: fmt.Sprintf("Campaign '%s' (ID %s) was deleted", existingCampaignForAudit.CampaignName, campaignID),
	}
	
	if err := h.CampaignMgr.LogAuditEvent(campaignID, dnsCampaignApiType, auditEntry); err != nil {
		log.Printf("WARN: Error logging audit event for campaign deletion %s: %v. Campaign was already deleted from main data maps.", campaignID, err)
	}
	log.Printf("DEBUG: Audit event logged for deletion of campaign %s.", campaignID)

	w.WriteHeader(http.StatusNoContent)
	log.Printf("DEBUG: Sent 204 No Content for campaign %s deletion.", campaignID)
}

// UploadDNSCampaignDomainsHandler handles uploading a list of domains to a DNS campaign.
// POST /api/v1/campaigns/dns/{campaignId}/upload
func (h *APIHandler) UploadDNSCampaignDomainsHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("DEBUG: UploadDNSCampaignDomainsHandler invoked for request: %s %s", r.Method, r.URL.Path)
	vars := mux.Vars(r)
	campaignID, ok := vars["campaignId"]
	if !ok {
		log.Printf("DEBUG: Campaign ID missing for UploadDNSCampaignDomainsHandler")
		respondWithError(w, http.StatusBadRequest, "Campaign ID is missing in URL path")
		return
	}
	log.Printf("DEBUG: Uploading domains for campaign ID: %s", campaignID)

	campaignData, err := h.CampaignMgr.GetCampaign(campaignID, dnsCampaignApiType)
	if err != nil {
		log.Printf("DEBUG: Campaign with ID %s not found for domain upload (GetCampaign error: %v)", campaignID, err)
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("Campaign with ID %s not found", campaignID))
		return
	}
	existingCampaign, ok := campaignData.(*dnsvalidation.DNSValidationCampaign)
	if !ok {
		log.Printf("ERROR: Retrieved campaign data for ID %s is of unexpected type during domain upload", campaignID)
		respondWithError(w, http.StatusInternalServerError, "Retrieved campaign data is of unexpected type")
		return
	}

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		log.Printf("ERROR: Failed to parse multipart form for campaign %s: %v", campaignID, err)
		respondWithError(w, http.StatusBadRequest, "Failed to parse multipart form: "+err.Error())
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		log.Printf("ERROR: No file uploaded or wrong form field name for campaign %s: %v", campaignID, err)
		respondWithError(w, http.StatusBadRequest, "File upload error: "+err.Error()+". Expected form field name 'file'.")
		return
	}
	defer file.Close()

	log.Printf("DEBUG: Received file upload: %s, Size: %d, MIME Header: %v for campaign %s", 
		handler.Filename, handler.Size, handler.Header, campaignID)

	mimeType := handler.Header.Get("Content-Type")
	if mimeType != "text/plain" && !strings.HasSuffix(strings.ToLower(handler.Filename), ".txt") {
		log.Printf("WARN: Invalid file type uploaded for campaign %s: %s (MIME: %s)", campaignID, handler.Filename, mimeType)
		respondWithError(w, http.StatusBadRequest, "Invalid file type. Please upload a .txt file.")
		return
	}

	var newCampaignItems []interface{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			newItem := &dnsvalidation.DNSValidationCampaignItem{
				Domain:           domain,
				ValidationStatus: campaigns.StatusPending,
				LastCheckedAt:    time.Time{},
				ResultsByPersona: make(map[string]*dnsvalidator.ValidationResult), // Initialize for multi-persona results
			}
			newCampaignItems = append(newCampaignItems, newItem)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("ERROR: Error reading uploaded file for campaign %s: %v", campaignID, err)
		respondWithError(w, http.StatusInternalServerError, "Error reading uploaded file: "+err.Error())
		return
	}

	if len(newCampaignItems) == 0 {
		log.Printf("INFO: No valid domains found in uploaded file for campaign %s", campaignID)
		respondWithError(w, http.StatusBadRequest, "No valid domains found in the uploaded file.")
		return
	}
	log.Printf("DEBUG: Parsed %d domains from file for campaign %s", len(newCampaignItems), campaignID)

	if err := h.CampaignMgr.AddCampaignItems(campaignID, dnsCampaignApiType, newCampaignItems); err != nil {
		log.Printf("ERROR: Failed to add campaign items to store for campaign %s: %v", campaignID, err)
		respondWithError(w, http.StatusInternalServerError, "Failed to add domains to campaign: "+err.Error())
		return
	}

	existingCampaign.InitialNumberOfDomains += len(newCampaignItems)
	existingCampaign.UpdatedAt = time.Now().UTC()
	uploadEvent := campaigns.UploadEvent{
		Filename:   handler.Filename,
		UploadedAt: existingCampaign.UpdatedAt,
	}
	if existingCampaign.UploadHistory == nil {
		existingCampaign.UploadHistory = make([]campaigns.UploadEvent, 0)
	}
	existingCampaign.UploadHistory = append(existingCampaign.UploadHistory, uploadEvent)

	if err := h.CampaignMgr.UpdateCampaign(existingCampaign); err != nil {
		log.Printf("ERROR: Failed to update campaign %s after domain upload: %v", campaignID, err)
		respondWithError(w, http.StatusInternalServerError, "Failed to update campaign metadata after domain upload: "+err.Error())
		return
	}

	auditEntry := campaigns.CampaignAuditEntry{
		Timestamp:   existingCampaign.UpdatedAt,
		Action:      "Domains Uploaded",
		Description: fmt.Sprintf("%d domains uploaded from file '%s' to campaign '%s' (ID %s)", len(newCampaignItems), handler.Filename, existingCampaign.CampaignName, campaignID),
	}
	if err := h.CampaignMgr.LogAuditEvent(campaignID, dnsCampaignApiType, auditEntry); err != nil {
		log.Printf("WARN: Error logging audit event for domain upload to campaign %s: %v", campaignID, err)
	}

	log.Printf("INFO: Successfully uploaded %d domains to campaign %s", len(newCampaignItems), campaignID)
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":      fmt.Sprintf("Successfully uploaded %d domains.", len(newCampaignItems)),
		"domainsAdded": len(newCampaignItems),
		"campaignId":   campaignID,
	})
}

// GetDNSCampaignDomainsHandler handles fetching the list of domain items for a DNS campaign.
// GET /api/v1/campaigns/dns/{campaignId}/domains
func (h *APIHandler) GetDNSCampaignDomainsHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("DEBUG: GetDNSCampaignDomainsHandler invoked for request: %s %s", r.Method, r.URL.Path)
	vars := mux.Vars(r)
	campaignID, ok := vars["campaignId"]
	if !ok {
		log.Printf("DEBUG: Campaign ID missing for GetDNSCampaignDomainsHandler")
		respondWithError(w, http.StatusBadRequest, "Campaign ID is missing in URL path")
		return
	}
	log.Printf("DEBUG: Getting domains for campaign ID: %s", campaignID)

	_, err := h.CampaignMgr.GetCampaign(campaignID, dnsCampaignApiType)
	if err != nil {
		log.Printf("DEBUG: Campaign with ID %s not found when trying to get domains (GetCampaign error: %v)", campaignID, err)
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("Campaign with ID %s not found", campaignID))
		return
	}

	itemsData, err := h.CampaignMgr.GetCampaignItems(campaignID, dnsCampaignApiType, nil)
	if err != nil {
		log.Printf("ERROR: Failed to get campaign items for campaign %s: %v", campaignID, err)
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve domains for campaign: "+err.Error())
		return
	}

	dnsItems := make([]*dnsvalidation.DNSValidationCampaignItem, 0, len(itemsData))
	for _, itemData := range itemsData {
		dnsItem, ok := itemData.(*dnsvalidation.DNSValidationCampaignItem)
		if !ok {
			log.Printf("ERROR: Unexpected item type in campaign %s items list", campaignID)
			respondWithError(w, http.StatusInternalServerError, "Internal error: unexpected item type in campaign data")
			return
		}
		dnsItems = append(dnsItems, dnsItem)
	}

	log.Printf("DEBUG: Successfully retrieved %d domain items for campaign %s", len(dnsItems), campaignID)
	respondWithJSON(w, http.StatusOK, dnsItems)
}

// GetDNSCampaignResultsHandler handles fetching the results for a DNS campaign.
// GET /api/v1/campaigns/dns/{campaignId}/results
func (h *APIHandler) GetDNSCampaignResultsHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("DEBUG: GetDNSCampaignResultsHandler invoked for request: %s %s", r.Method, r.URL.Path)
	vars := mux.Vars(r)
	campaignID, ok := vars["campaignId"]
	if !ok {
		log.Printf("DEBUG: Campaign ID missing for GetDNSCampaignResultsHandler")
		respondWithError(w, http.StatusBadRequest, "Campaign ID is missing in URL path")
		return
	}
	log.Printf("DEBUG: Getting results for campaign ID: %s", campaignID)

	_, err := h.CampaignMgr.GetCampaign(campaignID, dnsCampaignApiType)
	if err != nil {
		log.Printf("DEBUG: Campaign with ID %s not found when trying to get results (GetCampaign error: %v)", campaignID, err)
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("Campaign with ID %s not found", campaignID))
		return
	}

	itemsData, err := h.CampaignMgr.GetCampaignItems(campaignID, dnsCampaignApiType, nil)
	if err != nil {
		log.Printf("ERROR: Failed to get campaign items for campaign results %s: %v", campaignID, err)
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve items for campaign results: "+err.Error())
		return
	}

	dnsItems := make([]*dnsvalidation.DNSValidationCampaignItem, 0, len(itemsData))
	for _, itemData := range itemsData {
		dnsItem, ok := itemData.(*dnsvalidation.DNSValidationCampaignItem)
		if !ok {
			log.Printf("ERROR: Unexpected item type in campaign %s items list for results", campaignID)
			respondWithError(w, http.StatusInternalServerError, "Internal error: unexpected item type in campaign results")
			return
		}
		dnsItems = append(dnsItems, dnsItem)
	}
	log.Printf("DEBUG: Successfully retrieved %d domain items as results for campaign %s", len(dnsItems), campaignID)
	respondWithJSON(w, http.StatusOK, dnsItems) 
}

// RetryDNSCampaignHandler handles marking failed domains in a DNS campaign for retry.
// POST /api/v1/campaigns/dns/{campaignId}/retry
func (h *APIHandler) RetryDNSCampaignHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("DEBUG: RetryDNSCampaignHandler invoked for request: %s %s", r.Method, r.URL.Path)
	vars := mux.Vars(r)
	campaignID, ok := vars["campaignId"]
	if !ok {
		log.Printf("DEBUG: Campaign ID missing for RetryDNSCampaignHandler")
		respondWithError(w, http.StatusBadRequest, "Campaign ID is missing in URL path")
		return
	}
	log.Printf("DEBUG: Retrying domains for campaign ID: %s", campaignID)

	campaignData, err := h.CampaignMgr.GetCampaign(campaignID, dnsCampaignApiType)
	if err != nil {
		log.Printf("DEBUG: Campaign with ID %s not found for retry (GetCampaign error: %v)", campaignID, err)
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("Campaign with ID %s not found", campaignID))
		return
	}
	
	existingCampaign, ok := campaignData.(*dnsvalidation.DNSValidationCampaign)
	if !ok {
		log.Printf("ERROR: Retrieved campaign data for ID %s is of unexpected type during retry operation", campaignID)
		respondWithError(w, http.StatusInternalServerError, "Retrieved campaign data is of unexpected type")
		return
	}

	itemsData, err := h.CampaignMgr.GetCampaignItems(campaignID, dnsCampaignApiType, nil)
	if err != nil {
		log.Printf("ERROR: Failed to get campaign items for campaign %s during retry: %v", campaignID, err)
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve domains for retry: "+err.Error())
		return
	}

	retriedCount := 0
	var lastStoreError error
	itemsUpdated := false

	for _, itemData := range itemsData {
		dnsItem, ok := itemData.(*dnsvalidation.DNSValidationCampaignItem)
		if !ok {
			log.Printf("ERROR: Unexpected item type in campaign %s items list during retry", campaignID)
			continue
		}

		// Updated for new model: check OverallValidationStatus if it exists, otherwise default to ValidationStatus
		itemFailed := dnsItem.ValidationStatus == campaigns.StatusFailed
		// If OverallValidationStatus is a field, uncomment and use:
		// itemFailed = itemFailed || dnsItem.OverallValidationStatus == campaigns.StatusFailed
		// For now, assuming only dnsItem.ValidationStatus is the primary status for an item needing retry.

		if itemFailed {
			dnsItem.ValidationStatus = campaigns.StatusPending      
			// If using OverallValidationStatus, set it too:
			// dnsItem.OverallValidationStatus = campaigns.StatusPending 
			dnsItem.ErrorDetails = ""                              
			dnsItem.ResultsByPersona = make(map[string]*dnsvalidator.ValidationResult) 
			dnsItem.MismatchDetected = false
			
			err := h.CampaignMgr.UpdateCampaignItem(campaignID, dnsCampaignApiType, dnsItem.Domain, dnsItem)
			if err != nil {
				log.Printf("ERROR: Failed to update item %s for campaign %s during retry: %v", dnsItem.Domain, campaignID, err)
				lastStoreError = err 
				continue
			}
			retriedCount++
			itemsUpdated = true
		}
	}

	if lastStoreError != nil && retriedCount == 0 {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to mark any domains for retry due to store errors: %v", lastStoreError))
		return
	}
	
	if itemsUpdated {
		existingCampaign.UpdatedAt = time.Now().UTC()
		if err := h.CampaignMgr.UpdateCampaign(existingCampaign); err != nil {
			log.Printf("ERROR: Failed to update campaign %s metadata after marking items for retry: %v", campaignID, err)
		}
		
		auditEntry := campaigns.CampaignAuditEntry{
			Timestamp:   existingCampaign.UpdatedAt,
			Action:      "Domains Retry Initiated",
			Description: fmt.Sprintf("%d domains in campaign '%s' (ID %s) marked for retry.", retriedCount, existingCampaign.CampaignName, campaignID),
		}
		if err := h.CampaignMgr.LogAuditEvent(campaignID, dnsCampaignApiType, auditEntry); err != nil {
			log.Printf("WARN: Error logging audit event for retry initiation for campaign %s: %v", campaignID, err)
		}
	}

	log.Printf("INFO: Marked %d domains for retry in campaign %s", retriedCount, campaignID)
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":      fmt.Sprintf("%d domains marked for retry.", retriedCount),
		"retriedCount": retriedCount,
		"campaignId":   campaignID,
	})
}

