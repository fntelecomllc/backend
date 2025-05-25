package dnsvalidation

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/fntelecomllc/domainflow/backend/internal/campaigns"
	"github.com/fntelecomllc/domainflow/backend/internal/config"
	"github.com/fntelecomllc/domainflow/backend/internal/dnsvalidator"
)

// DNSCampaignService handles the business logic for processing DNS validation campaigns.
type DNSCampaignService struct {
	campaignStore campaigns.CampaignStore
	dnsValidator  *dnsvalidator.DNSValidator // The actual DNS validation engine
	appConfig     *config.AppConfig        // For accessing persona configurations
}

// NewDNSCampaignService creates a new instance of DNSCampaignService.
func NewDNSCampaignService(
	cs campaigns.CampaignStore,
	dv *dnsvalidator.DNSValidator,
	cfg *config.AppConfig,
) *DNSCampaignService {
	if dv == nil { // Ensure dnsValidator is not nil
		// This should ideally be handled by the caller in main.go ensuring proper initialization.
		// For now, we log a fatal error if it's nil as the service cannot function.
		log.Fatalf("CRITICAL: DNSValidator cannot be nil for DNSCampaignService")
	}
	return &DNSCampaignService{
		campaignStore: cs,
		dnsValidator:  dv,
		appConfig:     cfg,
	}
}

// ProcessCampaign processes a DNS validation campaign by its ID.
// This version implements the multi-persona and fallback logic.
func (s *DNSCampaignService) ProcessCampaign(ctx context.Context, campaignID string) error {
	log.Printf("INFO: Service: Starting processing for DNS campaign ID: %s", campaignID)

	// 1. Fetch the campaign
	campaignData, err := s.campaignStore.GetCampaign(campaignID, campaigns.DNSType)
	if err != nil {
		log.Printf("ERROR: Service: Failed to fetch campaign %s for processing: %v", campaignID, err)
		return fmt.Errorf("failed to fetch campaign %s: %w", campaignID, err)
	}
	dnsCampaign, ok := campaignData.(*DNSValidationCampaign)
	if !ok {
		log.Printf("ERROR: Service: Fetched campaign %s is not of type DNSValidationCampaign", campaignID)
		return fmt.Errorf("campaign %s is of unexpected type", campaignID)
	}

	if dnsCampaign.Status != campaigns.StatusActive && dnsCampaign.Status != campaigns.StatusPending {
		log.Printf("INFO: Service: Campaign %s is not in an active/pending state (current status: %s), skipping processing.", campaignID, dnsCampaign.Status)
		return nil
	}
	if len(dnsCampaign.DNSPersonaIDs) == 0 {
		log.Printf("WARN: Service: Campaign %s has no DNS personas assigned. Skipping processing.", campaignID)
		// Optionally, set campaign status to failed or error here.
		dnsCampaign.Status = campaigns.StatusError
		dnsCampaign.UpdatedAt = time.Now().UTC()
		_ = s.campaignStore.UpdateCampaign(dnsCampaign) // Best effort update
		return fmt.Errorf("campaign %s has no DNS personas assigned", campaignID)
	}

	// 2. Fetch pending domain items
	// For now, we fetch all items and filter for pending ones in memory.
	// A more optimized approach would be to fetch only pending items from the store.
	itemsData, err := s.campaignStore.GetCampaignItems(campaignID, campaigns.DNSType, nil) 
	if err != nil {
		log.Printf("ERROR: Service: Failed to fetch items for campaign %s: %v", campaignID, err)
		return fmt.Errorf("failed to fetch items for campaign %s: %w", campaignID, err)
	}

	pendingItems := make([]*DNSValidationCampaignItem, 0)
	for _, itemData := range itemsData {
		dnsItem, ok := itemData.(*DNSValidationCampaignItem)
		if !ok {
			log.Printf("WARN: Service: Found item of unexpected type in campaign %s, skipping.", campaignID)
			continue
		}
		if dnsItem.ValidationStatus == campaigns.StatusPending {
			pendingItems = append(pendingItems, dnsItem)
		}
	}

	if len(pendingItems) == 0 {
		log.Printf("INFO: Service: No pending items found for campaign %s.", campaignID)
		// If the campaign was active and has no more pending items, it might be complete.
		if dnsCampaign.Status == campaigns.StatusActive {
			dnsCampaign.Status = campaigns.StatusCompleted
			dnsCampaign.UpdatedAt = time.Now().UTC()
			_ = s.campaignStore.UpdateCampaign(dnsCampaign)
			log.Printf("INFO: Service: Campaign %s marked as completed.", campaignID)
		}
		return nil
	}

	log.Printf("INFO: Service: Found %d pending items to process for campaign %s.", len(pendingItems), campaignID)
	processedInThisRunCount := 0

	for _, dnsItem := range pendingItems {
		log.Printf("INFO: Service: Processing domain '%s' for campaign %s", dnsItem.Domain, campaignID)
		dnsItem.ValidationStatus = campaigns.StatusActive // Mark item as active during processing
		s.campaignStore.UpdateCampaignItem(campaignID, campaigns.DNSType, dnsItem.Domain, dnsItem) // Persist active status

		itemOverallSuccess := false
		var firstSuccessfulResult *dnsvalidator.ValidationResult
		var lastPersonaError error

		dnsItem.ResultsByPersona = make(map[string]*dnsvalidator.ValidationResult) // Ensure map is initialized
		dnsItem.MismatchDetected = false

		for i, personaID := range dnsCampaign.DNSPersonaIDs {
			log.Printf("DEBUG: Service: Attempting domain '%s' with persona '%s' (campaign %s)", dnsItem.Domain, personaID, campaignID)
			
			personaConfig, err := s.appConfig.GetDNSPersonaConfigByID(personaID) // Assumes AppConfig has such a method
			if err != nil {
				log.Printf("WARN: Service: DNS Persona '%s' not found for campaign %s, domain %s. Skipping this persona. Error: %v", personaID, campaignID, dnsItem.Domain, err)
				dnsItem.ResultsByPersona[personaID] = &dnsvalidator.ValidationResult{Error: fmt.Sprintf("Persona config not found: %s", personaID), Status: dnsvalidator.StatusError}
				continue
			}

			// Perform validation
			// Note: dnsValidator.Validate takes dnsvalidator.DNSValidatorConfigJSON, ensure conversion or direct use
			validationResult, validationErr := s.dnsValidator.Validate(dnsItem.Domain, personaConfig.Config) // Pass personaConfig.Config
			if validationErr != nil {
				log.Printf("INFO: Service: Validation error for domain '%s' with persona '%s': %v", dnsItem.Domain, personaID, validationErr)
				if validationResult == nil { // Ensure result object exists for error storage
					validationResult = &dnsvalidator.ValidationResult{Status: dnsvalidator.StatusError}
				}
				if validationResult.Error == "" { validationResult.Error = validationErr.Error() }
				lastPersonaError = validationErr
			}
			dnsItem.ResultsByPersona[personaID] = validationResult

			// Check for success (e.g., resolved with IPs)
			if validationResult != nil && validationResult.Status == dnsvalidator.StatusResolved && len(validationResult.IPAddresses) > 0 {
				log.Printf("INFO: Service: Domain '%s' successfully validated by persona '%s'", dnsItem.Domain, personaID)
				itemOverallSuccess = true
				if firstSuccessfulResult == nil {
					firstSuccessfulResult = validationResult
				} else { // Mismatch detection logic (basic example: comparing primary status)
					if firstSuccessfulResult.Status != validationResult.Status { // More sophisticated comparison needed
						dnsItem.MismatchDetected = true
					}
				}
				// As per requirement: "Continue until one persona produces a successful result (then mark as completed/valid)"
				break // Break from persona loop
			}
			// If not successful, loop continues to the next persona (fallback)
		}

		// Update item status based on results
		if itemOverallSuccess {
			dnsItem.ValidationStatus = campaigns.StatusCompleted
			dnsItem.ErrorDetails = ""
		} else {
			dnsItem.ValidationStatus = campaigns.StatusFailed
			if lastPersonaError != nil {
				dnsItem.ErrorDetails = lastPersonaError.Error()
			} else {
				dnsItem.ErrorDetails = "Validation failed with all personas, no specific error from last attempt."
			}
		}
		dnsItem.LastCheckedAt = time.Now().UTC()
		if err := s.campaignStore.UpdateCampaignItem(campaignID, campaigns.DNSType, dnsItem.Domain, dnsItem); err != nil {
			log.Printf("ERROR: Service: Failed to update campaign item '%s' for campaign %s: %v", dnsItem.Domain, campaignID, err)
			// Decide how to handle this: stop processing, or continue with other items?
			// For now, log and continue, but this item won't reflect its processed state.
			continue // Skip to next item if update fails
		}
		processedInThisRunCount++
		log.Printf("INFO: Service: Finished processing domain '%s' for campaign %s. Overall Status: %s, Mismatch: %v", 
			dnsItem.Domain, campaignID, dnsItem.ValidationStatus, dnsItem.MismatchDetected)
	}

	// 3. Update Campaign Aggregates & Status
	if processedInThisRunCount > 0 {
		// Fetch the campaign again to avoid clobbering other potential updates to ProcessedDomainsCount
		// Or, manage ProcessedDomainsCount more carefully if processing is distributed/concurrent.
		// For a single-threaded processor, updating the fetched dnsCampaign object directly is okay.
		dnsCampaign.ProcessedDomainsCount += processedInThisRunCount
		dnsCampaign.UpdatedAt = time.Now().UTC()
		if dnsCampaign.InitialNumberOfDomains > 0 {
			dnsCampaign.Progress = (float64(dnsCampaign.ProcessedDomainsCount) / float64(dnsCampaign.InitialNumberOfDomains)) * 100
		}
	}

	// Check if all items are processed to mark campaign as completed
	allDone := true
	finalItemsData, _ := s.campaignStore.GetCampaignItems(campaignID, campaigns.DNSType, nil) // Re-fetch to check statuses
	for _, itemData := range finalItemsData {
		if dnsItem, ok := itemData.(*DNSValidationCampaignItem); ok {
			if dnsItem.ValidationStatus == campaigns.StatusPending || dnsItem.ValidationStatus == campaigns.StatusActive {
				allDone = false
				break
			}
		}
	}
	if allDone && len(finalItemsData) > 0 { // Ensure there were items to process
		dnsCampaign.Status = campaigns.StatusCompleted
		log.Printf("INFO: Service: All items processed for campaign %s. Marking as COMPLETED.", campaignID)
	}

	if err := s.campaignStore.UpdateCampaign(dnsCampaign); err != nil {
		log.Printf("ERROR: Service: Failed to update campaign %s after processing: %v", campaignID, err)
		// This is a significant error, as campaign progress/status might not be saved.
		return fmt.Errorf("failed to update campaign %s after processing: %w", campaignID, err)
	}

	log.Printf("INFO: Service: Finished processing cycle for DNS campaign ID: %s. Items processed in this run: %d", campaignID, processedInThisRunCount)
	return nil
}
