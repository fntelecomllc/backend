package models

// GeneralErrorResponse is a generic error response structure for the API
type GeneralErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}
