package campaigns

import "time"

// CampaignType represents the type of a campaign.
type CampaignType string

const (
	// DNSType is the type for DNS validation campaigns.
	DNSType CampaignType = "DNS_VALIDATION"
	// HTTPType is the type for HTTP validation campaigns (if/when implemented).
	// HTTPType CampaignType = "HTTP_VALIDATION"
	// Add other campaign type constants here.
)

// CampaignStatus defines the possible statuses of a campaign.
type CampaignStatus string

const (
	StatusPending   CampaignStatus = "pending"
	StatusActive    CampaignStatus = "active"
	StatusPaused    CampaignStatus = "paused"
	StatusCompleted CampaignStatus = "completed"
	StatusFailed    CampaignStatus = "failed"
	StatusCancelled CampaignStatus = "cancelled"
	StatusError     CampaignStatus = "error"
	StatusRetrying  CampaignStatus = "retrying"
)

// BaseCampaign contains common fields for all campaign types.
type BaseCampaign struct {
	CampaignID   string         `json:"campaignId"`
	CampaignName string         `json:"campaignName"`
	Description  string         `json:"description,omitempty"`
	CampaignType CampaignType   `json:"campaignType"` // Changed from string to CampaignType
	Status       CampaignStatus `json:"status"`
	CreatedAt    time.Time      `json:"createdAt"`
	UpdatedAt    time.Time      `json:"updatedAt"`
	CreatedBy    string         `json:"createdBy,omitempty"` // UserID or system identifier
	OwnerID      string         `json:"ownerId,omitempty"`   // UserID for multi-user contexts
	Notes        string         `json:"notes,omitempty"`
	Tags         []string       `json:"tags,omitempty"`
	AuditLog     []CampaignAuditEntry `json:"auditLog,omitempty"`
	Progress     float64        `json:"progress"` // Calculated: 0.0 to 100.0
	ResultFilePath string       `json:"resultFilePath,omitempty"`
}

// CampaignAuditEntry records a significant event in a campaign's lifecycle.
type CampaignAuditEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	UserID      string    `json:"userId,omitempty"`
	Action      string    `json:"action"`
	Description string    `json:"description,omitempty"`
}

// UploadEvent records details of a file upload related to a campaign.
type UploadEvent struct {
	Filename    string    `json:"filename"`
	FileID      string    `json:"fileId,omitempty"` // Identifier for stored file if applicable
	UploadedAt  time.Time `json:"uploadedAt"`
	UploadedBy  string    `json:"uploadedBy,omitempty"` // UserID
}
