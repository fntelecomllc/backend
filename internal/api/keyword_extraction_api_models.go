package api

import (
	"github.com/fntelecomllc/domainflow/backend/internal/keywordextractor"
)

// KeywordExtractionRequestItem defines a single item for keyword extraction.
type KeywordExtractionRequestItem struct {
	URL           string  `json:"url"`
	HTTPPersonaID *string `json:"httpPersonaId,omitempty"`
	DNSPersonaID  *string `json:"dnsPersonaId,omitempty"` // For DNS resolution during content fetching
	KeywordSetID  string  `json:"keywordSetId"`
}

// BatchKeywordExtractionRequest defines the request for batch keyword extraction.
type BatchKeywordExtractionRequest struct {
	Items []KeywordExtractionRequestItem `json:"items"`
}

// KeywordExtractionAPIResult defines the result for a single URL's keyword extraction.
type KeywordExtractionAPIResult struct {
	URL               string                                         `json:"url"`
	HTTPPersonaIDUsed *string                                        `json:"httpPersonaIdUsed,omitempty"`
	DNSPersonaIDUsed  *string                                        `json:"dnsPersonaIdUsed,omitempty"`
	KeywordSetIDUsed  string                                         `json:"keywordSetIdUsed"`
	Matches           []keywordextractor.KeywordExtractionResult `json:"matches,omitempty"`
	Error             string                                         `json:"error,omitempty"`
	FinalURL          string                                         `json:"finalUrl,omitempty"`    // URL after redirects
	StatusCode        int                                            `json:"statusCode,omitempty"` // HTTP status code from fetching
}

// BatchKeywordExtractionResponse defines the response for batch keyword extraction.
type BatchKeywordExtractionResponse struct {
	Results []KeywordExtractionAPIResult `json:"results"`
}

// StreamKeywordExtractionRequestItem defines parameters for stream keyword extraction (via query params).
// This isn't a request body struct, but represents the expected parameters.
// URL and KeywordSetID are mandatory.
type StreamKeywordExtractionRequestItem struct {
	URL           string
	HTTPPersonaID *string
	DNSPersonaID  *string
	KeywordSetID  string
}
