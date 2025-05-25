package dnsvalidation

import (
	"time"

	"github.com/fntelecomllc/domainflow/backend/internal/campaigns"
	"github.com/fntelecomllc/domainflow/backend/internal/dnsvalidator"
)

// DNSValidationCampaign defines the structure for a DNS validation campaign.
type DNSValidationCampaign struct {
	campaigns.BaseCampaign
	DomainInputSource      string   `json:"domainInputSource,omitempty"` // e.g., file path, list ID
	SourceMode             string   `json:"sourceMode,omitempty"`        // e.g., "file", "list"
	InitialNumberOfDomains int      `json:"initialNumberOfDomains"`
	ProcessedDomainsCount  int      `json:"processedDomainsCount"`
	DNSPersonaIDs          []string `json:"dnsPersonaIds"` // List of DNS Persona IDs to use
	ProxyAssignmentID      string   `json:"proxyAssignmentId,omitempty"` // Optional: if DNS queries are to be proxied
	UploadHistory          []campaigns.UploadEvent `json:"uploadHistory,omitempty"`
}

// DNSValidationCampaignItem defines the structure for an individual domain within a DNS validation campaign.
type DNSValidationCampaignItem struct {
	Domain            string                                   `json:"domain"`
	ValidationStatus  campaigns.CampaignStatus                 `json:"validationStatus"` // Overall status for this domain across all personas
	LastCheckedAt     time.Time                                `json:"lastCheckedAt,omitempty"`
	ErrorDetails      string                                   `json:"errorDetails,omitempty"`      // For general errors related to processing this item, not specific to a persona
	ResultsByPersona  map[string]*dnsvalidator.ValidationResult `json:"resultsByPersona,omitempty"` // Keyed by Persona ID
	MismatchDetected  bool                                     `json:"mismatchDetected,omitempty"` // True if results from different personas for this domain show discrepancies
}
