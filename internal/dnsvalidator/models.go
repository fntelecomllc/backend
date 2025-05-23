package dnsvalidator

// ValidationResult holds the result of a single domain DNS validation
type ValidationResult struct {
	Domain     string   `json:"domain"`
	Status     string   `json:"status"` // e.g., "Resolved", "Not Found", "Error", "Timeout"
	IPs        []string `json:"ips,omitempty"`
	Resolver   string   `json:"resolver,omitempty"`
	Error      string   `json:"error,omitempty"`
	Timestamp  string   `json:"timestamp"` // ISO 8601
	DurationMs int64    `json:"durationMs"`  // Duration of the validation attempt in milliseconds
}
