package campaigns

// CampaignStore defines the interface for campaign data storage operations.
// It is designed to be generic enough to handle various campaign types.
type CampaignStore interface {
	// CreateCampaign saves a new campaign (e.g., DNSValidationCampaign, HTTPValidationCampaign) to the store.
	// The actual campaign type will be asserted by the implementation.
	CreateCampaign(campaign interface{}) error

	// GetCampaign retrieves a specific campaign by its ID and type.
	// The campaignType parameter helps in namespacing or table selection if needed.
	GetCampaign(campaignID string, campaignType string) (interface{}, error)

	// UpdateCampaign updates an existing campaign.
	// The campaign data should be a pointer to the campaign struct to be updated.
	UpdateCampaign(campaign interface{}) error

	// DeleteCampaign removes a campaign from the store.
	DeleteCampaign(campaignID string, campaignType string) error

	// ListCampaigns retrieves a list of campaigns, potentially filtered and paginated.
	// filters: map[string]string for simple key-value filtering (e.g., status: "active").
	// paginationOpts: placeholder for pagination parameters (e.g., limit, offset, page).
	ListCampaigns(campaignType string, filters map[string]string, paginationOpts interface{}) ([]interface{}, error)

	// AddCampaignItem adds an item (e.g., a domain to validate) to a specific campaign.
	// The item type will be specific to the campaign (e.g., DNSValidationCampaignItem).
	AddCampaignItem(campaignID string, campaignType string, item interface{}) error

	// AddCampaignItems adds multiple items to a specific campaign.
	AddCampaignItems(campaignID string, campaignType string, items []interface{}) error

	// UpdateCampaignItem updates a specific item within a campaign.
	// itemID could be the domain name or a unique ID for the item.
	UpdateCampaignItem(campaignID string, campaignType string, itemID string, updates interface{}) error

	// GetCampaignItems retrieves items associated with a campaign, with potential filtering/pagination.
	GetCampaignItems(campaignID string, campaignType string, filterOpts interface{}) ([]interface{}, error)

	// GetCampaignResultPath retrieves the path for the campaign's exportable results.
	// This might be relevant if results are stored as files.
	GetCampaignResultPath(campaignID string, campaignType string) (string, error)
	SetCampaignResultPath(campaignID string, campaignType string, path string) error

	// LogAuditEvent records an audit entry for a campaign.
	LogAuditEvent(campaignID string, campaignType string, entry CampaignAuditEntry) error
}
