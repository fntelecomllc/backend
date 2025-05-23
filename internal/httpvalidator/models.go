package httpvalidator

// ValidationResult holds the result of a single domain HTTP validation
type ValidationResult struct {
	Domain            string              `json:"domain"`
	Status            string              `json:"status"` // e.g., "OK", "Not Found", "Error", "Timeout", "Redirect Limit Reached"
	StatusCode        int                 `json:"statusCode,omitempty"`
	FinalURL          string              `json:"finalUrl,omitempty"`    // URL after redirects
	ContentHash       string              `json:"contentHash,omitempty"` // SHA256 hash of the (potentially limited) response body
	ContentLength     int                 `json:"contentLength,omitempty"` // Length of body read for hashing
    ActualContentLength int64             `json:"actualContentLength,omitempty"` // From Content-Length header or full body if read
	ContentHashError  string              `json:"contentHashError,omitempty"` // Error if hashing failed
	ResponseHeaders   map[string][]string `json:"responseHeaders,omitempty"`
	AntiBotIndicators map[string]string   `json:"antiBotIndicators,omitempty"` // Simple key-value pairs
	Error             string              `json:"error,omitempty"`
	Timestamp         string              `json:"timestamp"`       // ISO 8601
	DurationMs        int64               `json:"durationMs"`    // Duration of the validation attempt
	RawBody           []byte              `json:"-"`                // Raw response body, not included in JSON response by default
}
