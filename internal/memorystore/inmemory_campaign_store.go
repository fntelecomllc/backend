package memorystore

import (
	"fmt"
	"sync"
	"time"

	"github.com/fntelecomllc/domainflow/backend/internal/campaigns"
	"github.com/fntelecomllc/domainflow/backend/internal/campaigns/dnsvalidation"
)

const (
	// Define constants for campaign types for consistency.
	// For now, let's use a string directly and ensure it matches what handlers/services expect.
	dnsCampaignType = "DNS_VALIDATION"
)

// InMemoryCampaignStore provides an in-memory implementation of the CampaignStore interface.
type InMemoryCampaignStore struct {
	mu             sync.RWMutex
	dnsCampaigns   map[string]*dnsvalidation.DNSValidationCampaign
	dnsCampaignItems map[string]map[string]*dnsvalidation.DNSValidationCampaignItem // map[campaignID]map[domainName]item
}

// NewInMemoryCampaignStore creates a new instance of InMemoryCampaignStore.
func NewInMemoryCampaignStore() *InMemoryCampaignStore {
	return &InMemoryCampaignStore{
		dnsCampaigns:   make(map[string]*dnsvalidation.DNSValidationCampaign),
		dnsCampaignItems: make(map[string]map[string]*dnsvalidation.DNSValidationCampaignItem),
	}
}

// CreateCampaign saves a new campaign to the store.
func (s *InMemoryCampaignStore) CreateCampaign(campaign interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch camp := campaign.(type) {
	case *dnsvalidation.DNSValidationCampaign:
		if _, exists := s.dnsCampaigns[camp.CampaignID]; exists {
			return fmt.Errorf("DNS campaign with ID %s already exists", camp.CampaignID)
		}
		if camp.AuditLog == nil {
			camp.AuditLog = []campaigns.CampaignAuditEntry{}
		}
		s.dnsCampaigns[camp.CampaignID] = camp
		s.dnsCampaignItems[camp.CampaignID] = make(map[string]*dnsvalidation.DNSValidationCampaignItem)
		return nil
	default:
		return fmt.Errorf("unsupported campaign type: %T", campaign)
	}
}

// GetCampaign retrieves a specific campaign by its ID and type.
func (s *InMemoryCampaignStore) GetCampaign(campaignID string, campaignType string) (interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch campaignType {
	case dnsCampaignType: // Assuming dnsCampaignType is defined, e.g., "DNS_VALIDATION"
		campaign, exists := s.dnsCampaigns[campaignID]
		if !exists {
			return nil, fmt.Errorf("DNS campaign with ID %s not found", campaignID)
		}
		return campaign, nil
	default:
		return nil, fmt.Errorf("unsupported campaign type: %s", campaignType)
	}
}

// UpdateCampaign updates an existing campaign.
func (s *InMemoryCampaignStore) UpdateCampaign(campaign interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch camp := campaign.(type) {
	case *dnsvalidation.DNSValidationCampaign:
		if _, exists := s.dnsCampaigns[camp.CampaignID]; !exists {
			return fmt.Errorf("DNS campaign with ID %s not found for update", camp.CampaignID)
		}
		s.dnsCampaigns[camp.CampaignID] = camp
		return nil
	default:
		return fmt.Errorf("unsupported campaign type for update: %T", campaign)
	}
}

// DeleteCampaign removes a campaign from the store.
func (s *InMemoryCampaignStore) DeleteCampaign(campaignID string, campaignType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch campaignType {
	case dnsCampaignType:
		if _, exists := s.dnsCampaigns[campaignID]; !exists {
			return fmt.Errorf("DNS campaign with ID %s not found for delete", campaignID)
		}
		delete(s.dnsCampaigns, campaignID)
		delete(s.dnsCampaignItems, campaignID) 
		return nil
	default:
		return fmt.Errorf("unsupported campaign type for delete: %s", campaignType)
	}
}

// ListCampaigns retrieves a list of campaigns.
func (s *InMemoryCampaignStore) ListCampaigns(campaignType string, filters map[string]string, paginationOpts interface{}) ([]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []interface{}
	switch campaignType {
	case dnsCampaignType:
		for _, camp := range s.dnsCampaigns {
			match := true
			if statusFilter, ok := filters["status"]; ok {
				if string(camp.Status) != statusFilter {
					match = false
				}
			}
			if match {
				result = append(result, camp)
			}
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported campaign type for list: %s", campaignType)
	}
}

// AddCampaignItem adds an item to a specific campaign.
func (s *InMemoryCampaignStore) AddCampaignItem(campaignID string, campaignType string, item interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch campaignType {
	case dnsCampaignType:
		dnsItem, ok := item.(*dnsvalidation.DNSValidationCampaignItem)
		if !ok {
			return fmt.Errorf("invalid item type for DNS campaign: %T", item)
		}
		if _, campExists := s.dnsCampaigns[campaignID]; !campExists {
			return fmt.Errorf("DNS campaign with ID %s not found", campaignID)
		}
		if s.dnsCampaignItems[campaignID] == nil {
			s.dnsCampaignItems[campaignID] = make(map[string]*dnsvalidation.DNSValidationCampaignItem)
		}
		s.dnsCampaignItems[campaignID][dnsItem.Domain] = dnsItem
		return nil
	default:
		return fmt.Errorf("unsupported campaign type for adding item: %s", campaignType)
	}
}

// AddCampaignItems adds multiple items to a specific campaign.
func (s *InMemoryCampaignStore) AddCampaignItems(campaignID string, campaignType string, items []interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch campaignType {
	case dnsCampaignType:
		if _, campExists := s.dnsCampaigns[campaignID]; !campExists {
			return fmt.Errorf("DNS campaign with ID %s not found", campaignID)
		}
		if s.dnsCampaignItems[campaignID] == nil {
			s.dnsCampaignItems[campaignID] = make(map[string]*dnsvalidation.DNSValidationCampaignItem)
		}
		for _, i := range items {
			dnsItem, ok := i.(*dnsvalidation.DNSValidationCampaignItem)
			if !ok {
				return fmt.Errorf("invalid item type for DNS campaign in batch: %T", i)
			}
			s.dnsCampaignItems[campaignID][dnsItem.Domain] = dnsItem
		}
		return nil
	default:
		return fmt.Errorf("unsupported campaign type for adding items: %s", campaignType)
	}
}

// UpdateCampaignItem updates a specific item within a campaign.
func (s *InMemoryCampaignStore) UpdateCampaignItem(campaignID string, campaignType string, itemID string, updates interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch campaignType {
	case dnsCampaignType:
		updatedItem, ok := updates.(*dnsvalidation.DNSValidationCampaignItem)
		if !ok {
			return fmt.Errorf("invalid update type for DNS campaign item: %T", updates)
		}
		if _, campExists := s.dnsCampaigns[campaignID]; !campExists {
			return fmt.Errorf("DNS campaign with ID %s not found", campaignID)
		}
		if campaignItems, itemsExist := s.dnsCampaignItems[campaignID]; itemsExist {
			if _, itemExists := campaignItems[itemID]; !itemExists {
				return fmt.Errorf("item with ID %s not found in DNS campaign %s", itemID, campaignID)
			}
			campaignItems[itemID] = updatedItem
			return nil
		}
		return fmt.Errorf("item map not initialized for DNS campaign %s", campaignID)

	default:
		return fmt.Errorf("unsupported campaign type for updating item: %s", campaignType)
	}
}

// GetCampaignItems retrieves items associated with a campaign.
func (s *InMemoryCampaignStore) GetCampaignItems(campaignID string, campaignType string, filterOpts interface{}) ([]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch campaignType {
	case dnsCampaignType:
		if _, campExists := s.dnsCampaigns[campaignID]; !campExists {
			return nil, fmt.Errorf("DNS campaign with ID %s not found", campaignID)
		}
		itemsMap, exists := s.dnsCampaignItems[campaignID]
		if !exists {
			return []interface{}{}, nil
		}
		var result []interface{}
		for _, item := range itemsMap {
			result = append(result, item)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported campaign type for getting items: %s", campaignType)
	}
}

// LogAuditEvent records an audit entry for a campaign.
func (s *InMemoryCampaignStore) LogAuditEvent(campaignID string, campaignType string, entry campaigns.CampaignAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch campaignType {
	case dnsCampaignType:
		campaign, exists := s.dnsCampaigns[campaignID]
		if !exists {
			return fmt.Errorf("DNS campaign with ID %s not found for audit logging", campaignID)
		}
		if entry.Timestamp.IsZero() {
			entry.Timestamp = time.Now()
		}
		campaign.AuditLog = append(campaign.AuditLog, entry)
		return nil
	default:
		return fmt.Errorf("unsupported campaign type for audit logging: %s", campaignType)
	}
}

// GetCampaignResultPath retrieves the path for the campaign's exportable results.
func (s *InMemoryCampaignStore) GetCampaignResultPath(campaignID string, campaignType string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch campaignType {
	case dnsCampaignType:
		campaign, exists := s.dnsCampaigns[campaignID]
		if !exists {
			return "", fmt.Errorf("DNS campaign with ID %s not found", campaignID)
		}
		return campaign.ResultFilePath, nil
	default:
		return "", fmt.Errorf("unsupported campaign type: %s", campaignType)
	}
}

// SetCampaignResultPath sets the path for the campaign's exportable results.
func (s *InMemoryCampaignStore) SetCampaignResultPath(campaignID string, campaignType string, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch campaignType {
	case dnsCampaignType:
		campaign, exists := s.dnsCampaigns[campaignID]
		if !exists {
			return fmt.Errorf("DNS campaign with ID %s not found", campaignID)
		}
		campaign.ResultFilePath = path
		return nil
	default:
		return fmt.Errorf("unsupported campaign type: %s", campaignType)
	}
}

// Ensure InMemoryCampaignStore implements CampaignStore interface from the campaigns package
var _ campaigns.CampaignStore = (*InMemoryCampaignStore)(nil)
