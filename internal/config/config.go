// File: backend/internal/config/config.go
package config

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp" // Added for regex compilation
	"strings"
	"time"
)

const (
	dnsPersonasConfigFilename      = "dns_personas.config.json"
	httpPersonasConfigFilename     = "http_personas.config.json"
	proxiesConfigFilename          = "proxies.config.json"
	keywordsConfigFilename         = "keywords.config.json" // Added for keyword sets
	DefaultRateLimitDPS            = 10.0
	DefaultRateLimitBurst          = 5
	DefaultHTTPRateLimitDPS        = 5.0
	DefaultHTTPRateLimitBurst      = 3
	DefaultSystemAPIKeyPlaceholder = "SET_A_REAL_KEY_IN_CONFIG_OR_ENV_d9f8s7d9f8s7d9f8"
	DefaultStreamChunkSize         = 200 
)

// --- Struct Definitions ---

type DNSPersona struct { /* ... same ... */ ID string `json:"id"`; Name string `json:"name"`; Description string `json:"description"`; Config DNSValidatorConfigJSON `json:"config"`}
type TLSClientHelloConfig struct { /* ... same ... */ MinVersion string `json:"minVersion,omitempty"`; MaxVersion string `json:"maxVersion,omitempty"`; CipherSuites []string `json:"cipherSuites,omitempty"`; CurvePreferences []string `json:"curvePreferences,omitempty"`}
type HTTP2SettingsConfig struct { /* ... same ... */ Enabled *bool `json:"enabled,omitempty"`}
type CookieHandlingConfig struct { /* ... same ... */ Mode string `json:"mode,omitempty"`}
type HTTPPersona struct { /* ... same ... */ ID string `json:"id"`; Name string `json:"name"`; Description string `json:"description"`; UserAgent string `json:"userAgent"`; Headers map[string]string `json:"headers"`; HeaderOrder []string `json:"headerOrder,omitempty"`; TLSClientHello TLSClientHelloConfig `json:"tlsClientHello,omitempty"`; HTTP2Settings HTTP2SettingsConfig `json:"http2Settings,omitempty"`; CookieHandling CookieHandlingConfig `json:"cookieHandling,omitempty"`; Notes string `json:"notes,omitempty"`; RateLimitDPS float64 `json:"rateLimitDps,omitempty"`; RateLimitBurst int `json:"rateLimitBurst,omitempty"`}

// ProxyConfigEntry now includes UserEnabled
type ProxyConfigEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Protocol    string `json:"protocol"`
	Address     string `json:"address"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	Notes       string `json:"notes,omitempty"`
	UserEnabled *bool  `json:"userEnabled,omitempty"` // New field: pointer to distinguish between not set, true, false
}

type CampaignDNSRotationMode string
const ( /* ... same ... */ RotationAllSequential CampaignDNSRotationMode = "all_sequential"; RotationAllRandomPerDomain CampaignDNSRotationMode = "all_random_per_domain"; RotationAllRandomPerRequest CampaignDNSRotationMode = "all_random_per_request"; RotationManualSequential CampaignDNSRotationMode = "manual_sequential"; RotationManualRandomPerDomain CampaignDNSRotationMode = "manual_random_per_domain"; RotationManualRandomPerRequest CampaignDNSRotationMode = "manual_random_per_request")
type CampaignDNSSettings struct { /* ... same ... */ CampaignID string `json:"campaignId"`; RotationMode CampaignDNSRotationMode `json:"rotationMode"`; SelectedPersonaIDs []string `json:"selectedPersonaIds,omitempty"`}
type AppConfig struct {
	Server         ServerConfig
	DNSValidator   DNSValidatorConfig
	HTTPValidator  HTTPValidatorConfig
	Logging        LoggingConfig
	DNSPersonas    []DNSPersona
	HTTPPersonas   []HTTPPersona
	Proxies        []ProxyConfigEntry
	KeywordSets    []KeywordSet // New field for keyword sets
	loadedFromPath string
}
func (ac *AppConfig) GetLoadedFromPath() string { return ac.loadedFromPath }
type LoggingConfig struct { /* ... same ... */ Level string `json:"level"` }

// KeywordRule defines a single rule for extracting keywords.
// Ensure Type is either "string" or "regex".
// CompiledRegex is populated internally if Type is "regex", not from JSON.
type KeywordRule struct {
	ID            string `json:"id,omitempty"`
	Pattern       string `json:"pattern"`
	Type          string `json:"type"` // "string" or "regex"
	CaseSensitive bool   `json:"caseSensitive"`
	Category      string `json:"category,omitempty"`
	ContextChars  int    `json:"contextChars,omitempty"` // Characters for context snippet
	CompiledRegex *regexp.Regexp `json:"-"`
}

// KeywordSet groups related keyword rules.
type KeywordSet struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Rules       []KeywordRule `json:"rules"`
}

type ServerConfig struct { /* ... same ... */ Port string `json:"port"`; APIKey string `json:"apiKey"`; StreamChunkSize int `json:"streamChunkSize,omitempty"`}
type DNSValidatorConfig struct { /* ... same ... */ Resolvers []string; UseSystemResolvers bool; QueryTimeout time.Duration; MaxDomainsPerRequest int; ResolverStrategy string; ResolversWeighted map[string]int; ResolversPreferredOrder []string; ConcurrentQueriesPerDomain int; QueryDelayMin time.Duration; QueryDelayMax time.Duration; MaxConcurrentGoroutines int; RateLimitDPS float64; RateLimitBurst int; QueryTimeoutSeconds int `json:"-"`; JSONResolvers []string `json:"-"`; JSONUseSystemResolvers bool `json:"-"`; JSONMaxDomainsPerRequest int `json:"-"`; JSONResolverStrategy string `json:"-"`; JSONResolversWeighted map[string]int `json:"-"`; JSONResolversPreferredOrder []string `json:"-"`; JSONConcurrentQueriesPerDomain int `json:"-"`; JSONQueryDelayMinMs int `json:"-"`; JSONQueryDelayMaxMs int `json:"-"`; JSONMaxConcurrentGoroutines int `json:"-"`; JSONRateLimitDPS float64 `json:"-"`; JSONRateLimitBurst int `json:"-"`; }
type DNSValidatorConfigJSON struct { /* ... same ... */ Resolvers []string `json:"resolvers"`; UseSystemResolvers bool `json:"useSystemResolvers"`; QueryTimeoutSeconds int `json:"queryTimeoutSeconds"`; MaxDomainsPerRequest int `json:"maxDomainsPerRequest"`; ResolverStrategy string `json:"resolverStrategy,omitempty"`; ResolversWeighted map[string]int `json:"resolversWeighted,omitempty"`; ResolversPreferredOrder []string `json:"resolversPreferredOrder,omitempty"`; ConcurrentQueriesPerDomain int `json:"concurrentQueriesPerDomain,omitempty"`; QueryDelayMinMs int `json:"queryDelayMinMs,omitempty"`; QueryDelayMaxMs int `json:"queryDelayMaxMs,omitempty"`; MaxConcurrentGoroutines int `json:"maxConcurrentGoroutines,omitempty"`; RateLimitDPS float64 `json:"rateLimitDps,omitempty"`; RateLimitBurst int `json:"rateLimitBurst,omitempty"`; }
type HTTPValidatorConfig struct { /* ... same ... */ UserAgents []string; DefaultHeaders map[string]string; RequestTimeout time.Duration; MaxRedirects int; MaxDomainsPerRequest int; AllowInsecureTLS bool; MaxConcurrentGoroutines int; RateLimitDPS float64; RateLimitBurst int; RequestTimeoutSeconds int `json:"-"`; JSONUserAgents []string `json:"-"`; JSONDefaultHeaders map[string]string `json:"-"`; JSONMaxRedirects int `json:"-"`; JSONMaxDomainsPerRequest int `json:"-"`; JSONAllowInsecureTLS bool `json:"-"`; JSONMaxConcurrentGoroutines int `json:"-"`; JSONRateLimitDPS float64 `json:"-"`; JSONRateLimitBurst int `json:"-"`; }
type HTTPValidatorConfigJSON struct { /* ... same ... */ UserAgents []string `json:"userAgents"`; DefaultHeaders map[string]string `json:"defaultHeaders"`; RequestTimeoutSeconds int `json:"requestTimeoutSeconds"`; MaxRedirects int `json:"maxRedirects"`; MaxDomainsPerRequest int `json:"maxDomainsPerRequest"`; AllowInsecureTLS bool `json:"allowInsecureTLS"`; MaxConcurrentGoroutines int `json:"maxConcurrentGoroutines,omitempty"`; RateLimitDPS float64 `json:"rateLimitDps,omitempty"`; RateLimitBurst int `json:"rateLimitBurst,omitempty"`; }
type AppConfigJSON struct { /* ... same ... */ Server ServerConfig `json:"server"`; DNSValidator DNSValidatorConfigJSON `json:"dnsValidator"`; HTTPValidator HTTPValidatorConfigJSON `json:"httpValidator"`; Logging LoggingConfig `json:"logging"`}

// LoadDNSPersonas, LoadHTTPPersonas, LoadProxies remain the same
func LoadDNSPersonas(configDir string) ([]DNSPersona, error) { filePath := filepath.Join(configDir, dnsPersonasConfigFilename); var personas []DNSPersona; data, err := ioutil.ReadFile(filePath); if err != nil { if os.IsNotExist(err) { log.Printf("Config: DNS Personas config file '%s' not found.", filePath); return personas, nil }; return nil, fmt.Errorf("failed to read DNS Personas config: %w", err) }; if err := json.Unmarshal(data, &personas); err != nil { return nil, fmt.Errorf("error unmarshalling DNS Personas: %w", err) }; log.Printf("Config: Loaded %d DNS Personas from '%s'", len(personas), filePath); return personas, nil }
func LoadHTTPPersonas(configDir string) ([]HTTPPersona, error) { filePath := filepath.Join(configDir, httpPersonasConfigFilename); var personas []HTTPPersona; data, err := ioutil.ReadFile(filePath); if err != nil { if os.IsNotExist(err) { log.Printf("Config: HTTP Personas config file '%s' not found.", filePath); return personas, nil }; return nil, fmt.Errorf("failed to read HTTP Personas config: %w", err) }; if err := json.Unmarshal(data, &personas); err != nil { return nil, fmt.Errorf("error unmarshalling HTTP Personas: %w", err) }; log.Printf("Config: Loaded %d HTTP Personas from '%s'", len(personas), filePath); return personas, nil }
func LoadProxies(configDir string) ([]ProxyConfigEntry, error) {
	filePath := filepath.Join(configDir, proxiesConfigFilename)
	var proxies []ProxyConfigEntry
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Config: Proxies config file '%s' not found. No pre-defined proxies will be loaded.", filePath)
			return proxies, nil 
		}
		return nil, fmt.Errorf("failed to read Proxies config file '%s': %w", filePath, err)
	}
	if err := json.Unmarshal(data, &proxies); err != nil {
		return nil, fmt.Errorf("error unmarshalling Proxies config file '%s': %w", filePath, err)
	}
	// Default UserEnabled to true if nil (not present in JSON)
	for i := range proxies {
		if proxies[i].UserEnabled == nil {
			defaultValue := true
			proxies[i].UserEnabled = &defaultValue
		}
	}
	log.Printf("Config: Loaded %d Proxies from '%s'", len(proxies), filePath)
	return proxies, nil
}

// LoadKeywordSets loads keyword definitions from the configuration file.
func LoadKeywordSets(configDir string) ([]KeywordSet, error) {
	filePath := filepath.Join(configDir, keywordsConfigFilename)
	var keywordSets []KeywordSet
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Config: Keyword Sets config file '%s' not found. No keyword sets will be loaded.", filePath)
			return keywordSets, nil // Return empty list, not an error
		}
		return nil, fmt.Errorf("failed to read Keyword Sets config file '%s': %w", filePath, err)
	}

	if err := json.Unmarshal(data, &keywordSets); err != nil {
		return nil, fmt.Errorf("error unmarshalling Keyword Sets from '%s': %w", filePath, err)
	}

	// Pre-compile regex patterns
	for i, ks := range keywordSets {
		for j, rule := range ks.Rules {
			if strings.ToLower(rule.Type) == "regex" {
				if rule.Pattern == "" {
					log.Printf("Config Warning: Keyword set '%s' ('%s'), Rule ID '%s' (or index %d) is of type regex but has empty pattern. Skipping compilation.", ks.ID, ks.Name, rule.ID, j)
					continue
				}
				// Apply case insensitivity at compile time if CaseSensitive is false for regex
				patternToCompile := rule.Pattern
				if !rule.CaseSensitive {
					patternToCompile = "(?i)" + rule.Pattern
				}
				compiled, err := regexp.Compile(patternToCompile)
				if err != nil {
					log.Printf("Config Warning: Failed to compile regex for keyword set '%s' ('%s'), Rule ID '%s' (pattern: '%s'): %v. This rule will be skipped.", ks.ID, ks.Name, rule.ID, rule.Pattern, err)
					keywordSets[i].Rules[j].CompiledRegex = nil // Ensure it's nil if compilation fails
				} else {
					keywordSets[i].Rules[j].CompiledRegex = compiled
				}
			} else if strings.ToLower(rule.Type) != "string" {
				log.Printf("Config Warning: Keyword set '%s' ('%s'), Rule ID '%s' (or index %d) has unknown type '%s'. It should be 'string' or 'regex'. This rule may not function as expected.", ks.ID, ks.Name, rule.ID, j, rule.Type)
			}
		}
	}

	log.Printf("Config: Loaded %d Keyword Sets from '%s'", len(keywordSets), filePath)
	return keywordSets, nil
}

// SaveDNSPersonas saves the DNS personas to their configuration file.
func SaveDNSPersonas(personas []DNSPersona, configDir string) error {
	filePath := filepath.Join(configDir, dnsPersonasConfigFilename)
	data, err := json.MarshalIndent(personas, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal DNS personas to JSON: %w", err)
	}
	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write DNS personas to file '%s': %w", filePath, err)
	}
	log.Printf("Config: Successfully saved %d DNS Personas to '%s'", len(personas), filePath)
	return nil
}

// SaveHTTPPersonas saves the HTTP personas to their configuration file.
func SaveHTTPPersonas(personas []HTTPPersona, configDir string) error {
	filePath := filepath.Join(configDir, httpPersonasConfigFilename)
	data, err := json.MarshalIndent(personas, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal HTTP personas to JSON: %w", err)
	}
	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write HTTP personas to file '%s': %w", filePath, err)
	}
	log.Printf("Config: Successfully saved %d HTTP Personas to '%s'", len(personas), filePath)
	return nil
}

// Load function
func Load(mainConfigPath string) (*AppConfig, error) {
	if mainConfigPath == "" {
		mainConfigPath = "config.json"
		log.Printf("Config: Main config path empty, using default: %s", mainConfigPath)
	}
	log.Printf("Config: Attempting to load main config from: %s", mainConfigPath)

	appCfgJSON := DefaultAppConfigJSON()
	var originalLoadError error

	data, err := ioutil.ReadFile(mainConfigPath)
	if err != nil {
		originalLoadError = err
		if os.IsNotExist(err) {
			log.Printf("Config: Main config file '%s' not found. Using defaults and attempting to save.", mainConfigPath)
			defaultAppCfg := ConvertJSONToAppConfig(appCfgJSON)
			defaultAppCfg.loadedFromPath = mainConfigPath
			if saveErr := Save(defaultAppCfg, mainConfigPath); saveErr != nil {
				log.Printf("Config: Failed to save default config file '%s': %v", mainConfigPath, saveErr)
			} else {
				log.Printf("Config: Saved default config to '%s'", mainConfigPath)
			}
		} else {
			log.Printf("Config: Error reading main config '%s': %v. Using defaults.", mainConfigPath, err)
		}
	} else {
		if errUnmarshal := json.Unmarshal(data, &appCfgJSON); errUnmarshal != nil {
			log.Printf("Config: Error unmarshalling main config '%s': %v. Using defaults for unparsed fields.", mainConfigPath, errUnmarshal)
			originalLoadError = errUnmarshal
		}
	}

	appConfig := ConvertJSONToAppConfig(appCfgJSON)
	appConfig.loadedFromPath = mainConfigPath

	if appConfig.Server.StreamChunkSize <= 0 {
		log.Printf("Config: StreamChunkSize is %d (invalid or not set), defaulting to %d.", appConfig.Server.StreamChunkSize, DefaultStreamChunkSize)
		appConfig.Server.StreamChunkSize = DefaultStreamChunkSize
	}

	configDir := filepath.Dir(mainConfigPath)
	if mainConfigPath == "" || filepath.Base(mainConfigPath) == mainConfigPath {
		cwd, errCwd := os.Getwd()
		if errCwd == nil {
			configDir = cwd
		} else {
			log.Printf("Config Warning: Could not get CWD for supplemental configs: %v.", errCwd)
		}
	}

	var loadErr error // Declare here for wider scope if needed, or within each block

	appConfig.DNSPersonas, loadErr = LoadDNSPersonas(configDir)
	if loadErr != nil {
		log.Printf("Config Notice: Error loading DNS Personas, proceeding with empty list: %v", loadErr)
		appConfig.DNSPersonas = []DNSPersona{}
	}

	appConfig.HTTPPersonas, loadErr = LoadHTTPPersonas(configDir)
	if loadErr != nil {
		log.Printf("Config Notice: Error loading HTTP Personas, proceeding with empty list: %v", loadErr)
		appConfig.HTTPPersonas = []HTTPPersona{}
	}

	proxiesFromFile, errProxies := LoadProxies(configDir)
	if errProxies != nil {
		log.Printf("Config Warning: Failed to load Proxies from file: %v. Proxy list will be empty.", errProxies)
		appConfig.Proxies = []ProxyConfigEntry{}
	} else {
		appConfig.Proxies = proxiesFromFile
	}

	appConfig.KeywordSets, loadErr = LoadKeywordSets(configDir)
	if loadErr != nil {
		log.Printf("Config Notice: Error loading Keyword Sets, proceeding with empty list: %v", loadErr)
		appConfig.KeywordSets = []KeywordSet{}
	}

	return appConfig, originalLoadError
}

// Conversion functions (ConvertJSONToDNSConfig, etc.) remain the same
func ConvertJSONToDNSConfig(jsonCfg DNSValidatorConfigJSON) DNSValidatorConfig { cfg := DNSValidatorConfig{ Resolvers: jsonCfg.Resolvers, UseSystemResolvers: jsonCfg.UseSystemResolvers, QueryTimeout: time.Duration(jsonCfg.QueryTimeoutSeconds) * time.Second, MaxDomainsPerRequest: jsonCfg.MaxDomainsPerRequest, ResolverStrategy: jsonCfg.ResolverStrategy, ResolversWeighted: jsonCfg.ResolversWeighted, ResolversPreferredOrder: jsonCfg.ResolversPreferredOrder, ConcurrentQueriesPerDomain: jsonCfg.ConcurrentQueriesPerDomain, QueryDelayMin: time.Duration(jsonCfg.QueryDelayMinMs) * time.Millisecond, QueryDelayMax: time.Duration(jsonCfg.QueryDelayMaxMs) * time.Millisecond, MaxConcurrentGoroutines: jsonCfg.MaxConcurrentGoroutines, RateLimitDPS: jsonCfg.RateLimitDPS, RateLimitBurst: jsonCfg.RateLimitBurst, QueryTimeoutSeconds: jsonCfg.QueryTimeoutSeconds, JSONResolvers: jsonCfg.Resolvers, JSONUseSystemResolvers: jsonCfg.UseSystemResolvers, JSONMaxDomainsPerRequest: jsonCfg.MaxDomainsPerRequest, JSONResolverStrategy: jsonCfg.ResolverStrategy, JSONResolversWeighted: jsonCfg.ResolversWeighted, JSONResolversPreferredOrder: jsonCfg.ResolversPreferredOrder, JSONConcurrentQueriesPerDomain: jsonCfg.ConcurrentQueriesPerDomain, JSONQueryDelayMinMs: jsonCfg.QueryDelayMinMs, JSONQueryDelayMaxMs: jsonCfg.QueryDelayMaxMs, JSONMaxConcurrentGoroutines: jsonCfg.MaxConcurrentGoroutines, JSONRateLimitDPS: jsonCfg.RateLimitDPS, JSONRateLimitBurst: jsonCfg.RateLimitBurst, }; if cfg.ResolverStrategy == "" { cfg.ResolverStrategy = "random_rotation"; cfg.JSONResolverStrategy = "random_rotation"}; if cfg.ConcurrentQueriesPerDomain <= 0 { cfg.ConcurrentQueriesPerDomain = 1; cfg.JSONConcurrentQueriesPerDomain = 1}; if cfg.MaxConcurrentGoroutines <= 0 { cfg.MaxConcurrentGoroutines = 10; cfg.JSONMaxConcurrentGoroutines = 10}; if jsonCfg.RateLimitDPS == 0 && cfg.RateLimitDPS == 0 { cfg.RateLimitDPS = DefaultRateLimitDPS; cfg.JSONRateLimitDPS = DefaultRateLimitDPS } else if cfg.RateLimitDPS < 0 { cfg.RateLimitDPS = DefaultRateLimitDPS; cfg.JSONRateLimitDPS = DefaultRateLimitDPS}; if jsonCfg.RateLimitBurst == 0 && cfg.RateLimitBurst == 0 { cfg.RateLimitBurst = DefaultRateLimitBurst; cfg.JSONRateLimitBurst = DefaultRateLimitBurst } else if cfg.RateLimitBurst < 0 { cfg.RateLimitBurst = DefaultRateLimitBurst; cfg.JSONRateLimitBurst = DefaultRateLimitBurst}; return cfg }
func ConvertDNSConfigToJSON(cfg DNSValidatorConfig) DNSValidatorConfigJSON { return DNSValidatorConfigJSON{ Resolvers: cfg.JSONResolvers, UseSystemResolvers: cfg.JSONUseSystemResolvers, QueryTimeoutSeconds: cfg.QueryTimeoutSeconds, MaxDomainsPerRequest: cfg.JSONMaxDomainsPerRequest, ResolverStrategy: cfg.JSONResolverStrategy, ResolversWeighted: cfg.JSONResolversWeighted, ResolversPreferredOrder: cfg.JSONResolversPreferredOrder, ConcurrentQueriesPerDomain: cfg.JSONConcurrentQueriesPerDomain, QueryDelayMinMs: cfg.JSONQueryDelayMinMs, QueryDelayMaxMs: cfg.JSONQueryDelayMaxMs, MaxConcurrentGoroutines: cfg.JSONMaxConcurrentGoroutines, RateLimitDPS: cfg.JSONRateLimitDPS, RateLimitBurst: cfg.JSONRateLimitBurst, } }
func ConvertJSONToHTTPConfig(jsonCfg HTTPValidatorConfigJSON) HTTPValidatorConfig { cfg := HTTPValidatorConfig{ UserAgents: jsonCfg.UserAgents, DefaultHeaders: jsonCfg.DefaultHeaders, RequestTimeout: time.Duration(jsonCfg.RequestTimeoutSeconds) * time.Second, MaxRedirects: jsonCfg.MaxRedirects, MaxDomainsPerRequest: jsonCfg.MaxDomainsPerRequest, AllowInsecureTLS: jsonCfg.AllowInsecureTLS, MaxConcurrentGoroutines: jsonCfg.MaxConcurrentGoroutines, RateLimitDPS: jsonCfg.RateLimitDPS, RateLimitBurst: jsonCfg.RateLimitBurst, RequestTimeoutSeconds: jsonCfg.RequestTimeoutSeconds, JSONUserAgents: jsonCfg.UserAgents, JSONDefaultHeaders: jsonCfg.DefaultHeaders, JSONMaxRedirects: jsonCfg.MaxRedirects, JSONMaxDomainsPerRequest: jsonCfg.MaxDomainsPerRequest, JSONAllowInsecureTLS: jsonCfg.AllowInsecureTLS, JSONMaxConcurrentGoroutines: jsonCfg.MaxConcurrentGoroutines, JSONRateLimitDPS: jsonCfg.RateLimitDPS, JSONRateLimitBurst: jsonCfg.RateLimitBurst, }; if cfg.MaxConcurrentGoroutines <= 0 { cfg.MaxConcurrentGoroutines = 15; cfg.JSONMaxConcurrentGoroutines = 15}; if jsonCfg.RateLimitDPS == 0 && cfg.RateLimitDPS == 0 { cfg.RateLimitDPS = DefaultHTTPRateLimitDPS; cfg.JSONRateLimitDPS = DefaultHTTPRateLimitDPS } else if cfg.RateLimitDPS < 0 { cfg.RateLimitDPS = DefaultHTTPRateLimitDPS; cfg.JSONRateLimitDPS = DefaultHTTPRateLimitDPS}; if jsonCfg.RateLimitBurst == 0 && cfg.RateLimitBurst == 0 { cfg.RateLimitBurst = DefaultHTTPRateLimitBurst; cfg.JSONRateLimitBurst = DefaultHTTPRateLimitBurst } else if cfg.RateLimitBurst < 0 { cfg.RateLimitBurst = DefaultHTTPRateLimitBurst; cfg.JSONRateLimitBurst = DefaultHTTPRateLimitBurst}; return cfg }
func ConvertHTTPConfigToJSON(cfg HTTPValidatorConfig) HTTPValidatorConfigJSON { return HTTPValidatorConfigJSON{ UserAgents: cfg.JSONUserAgents, DefaultHeaders: cfg.JSONDefaultHeaders, RequestTimeoutSeconds: cfg.RequestTimeoutSeconds, MaxRedirects: cfg.JSONMaxRedirects, MaxDomainsPerRequest: cfg.JSONMaxDomainsPerRequest, AllowInsecureTLS: cfg.JSONAllowInsecureTLS, MaxConcurrentGoroutines: cfg.JSONMaxConcurrentGoroutines, RateLimitDPS: cfg.JSONRateLimitDPS, RateLimitBurst: cfg.JSONRateLimitBurst, } }
func ConvertJSONToAppConfig(jsonCfg AppConfigJSON) *AppConfig { appCfg := &AppConfig{ Server: jsonCfg.Server, DNSValidator: ConvertJSONToDNSConfig(jsonCfg.DNSValidator), HTTPValidator: ConvertJSONToHTTPConfig(jsonCfg.HTTPValidator), Logging: jsonCfg.Logging, }; if appCfg.Server.StreamChunkSize <= 0 { appCfg.Server.StreamChunkSize = DefaultStreamChunkSize }; return appCfg }
func ConvertAppConfigToJSON(appCfg *AppConfig) AppConfigJSON { return AppConfigJSON{ Server: appCfg.Server, DNSValidator: ConvertDNSConfigToJSON(appCfg.DNSValidator), HTTPValidator: ConvertHTTPConfigToJSON(appCfg.HTTPValidator), Logging: appCfg.Logging, } }

// Save, SaveStructured, SaveProxies remain the same
func Save(cfg *AppConfig, filePath string) error { if filePath == "" { return fmt.Errorf("cannot save config, file path is empty") }; appCfgJSON := ConvertAppConfigToJSON(cfg); data, err := json.MarshalIndent(appCfgJSON, "", "  "); if err != nil { return fmt.Errorf("failed to marshal app config to JSON: %w", err) }; if err := ioutil.WriteFile(filePath, data, 0644); err != nil { return fmt.Errorf("failed to write app config to file '%s': %w", filePath, err) }; log.Printf("Config: Successfully saved main configuration to '%s'", filePath); return nil }
func SaveStructured(cfgJSON AppConfigJSON, filePath string) error { if filePath == "" { return fmt.Errorf("cannot save structured config, file path is empty") }; data, err := json.MarshalIndent(cfgJSON, "", "  "); if err != nil { return fmt.Errorf("failed to marshal app config JSON to data: %w", err) }; if err := ioutil.WriteFile(filePath, data, 0644); err != nil { return fmt.Errorf("failed to write app config to file '%s': %w", filePath, err) }; log.Printf("Config: Successfully saved main configuration (structured) to '%s'", filePath); return nil }
func SaveProxies(proxies []ProxyConfigEntry, configDir string) error { filePath := filepath.Join(configDir, proxiesConfigFilename); data, err := json.MarshalIndent(proxies, "", "  "); if err != nil { return fmt.Errorf("failed to marshal proxies to JSON: %w", err) }; if err := ioutil.WriteFile(filePath, data, 0644); err != nil { return fmt.Errorf("failed to write proxies to file '%s': %w", filePath, err) }; log.Printf("Config: Successfully saved %d proxies to '%s'", len(proxies), filePath); return nil }

// DefaultAppConfigJSON remains the same
func DefaultAppConfigJSON() AppConfigJSON { return AppConfigJSON{ Server: ServerConfig{ Port: "8080", APIKey: DefaultSystemAPIKeyPlaceholder, StreamChunkSize: DefaultStreamChunkSize, }, DNSValidator: DNSValidatorConfigJSON{ Resolvers: []string{"1.1.1.1:53", "8.8.8.8:53"}, UseSystemResolvers: false, QueryTimeoutSeconds: 5, MaxDomainsPerRequest: 100, ResolverStrategy: "random_rotation", ConcurrentQueriesPerDomain: 1, QueryDelayMinMs: 0, QueryDelayMaxMs: 50, MaxConcurrentGoroutines: 10, RateLimitDPS: DefaultRateLimitDPS, RateLimitBurst: DefaultRateLimitBurst, }, HTTPValidator: HTTPValidatorConfigJSON{ UserAgents: []string{ "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", }, DefaultHeaders: map[string]string{"Accept-Language": "en-US,en;q=0.9"}, RequestTimeoutSeconds: 15, MaxRedirects: 7, MaxDomainsPerRequest: 50, AllowInsecureTLS: false, MaxConcurrentGoroutines: 15, RateLimitDPS: DefaultHTTPRateLimitDPS, RateLimitBurst: DefaultHTTPRateLimitBurst, }, Logging: LoggingConfig{ Level: "INFO", }, } }
func DefaultConfig() *AppConfig { return ConvertJSONToAppConfig(DefaultAppConfigJSON()) }

// TLS helpers remain the same
var tlsVersionMap = map[string]uint16{ "SSL30": tls.VersionSSL30, "TLS10": tls.VersionTLS10, "TLS11": tls.VersionTLS11, "TLS12": tls.VersionTLS12, "TLS13": tls.VersionTLS13, }
var supportedCipherSuites = map[string]uint16{ "TLS_AES_128_GCM_SHA256": tls.TLS_AES_128_GCM_SHA256, "TLS_AES_256_GCM_SHA384": tls.TLS_AES_256_GCM_SHA384, "TLS_CHACHA20_POLY1305_SHA256": tls.TLS_CHACHA20_POLY1305_SHA256, "TLS_RSA_WITH_RC4_128_SHA": tls.TLS_RSA_WITH_RC4_128_SHA, "TLS_RSA_WITH_3DES_EDE_CBC_SHA": tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA": tls.TLS_RSA_WITH_AES_128_CBC_SHA, "TLS_RSA_WITH_AES_256_CBC_SHA": tls.TLS_RSA_WITH_AES_256_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA256": tls.TLS_RSA_WITH_AES_128_CBC_SHA256, "TLS_RSA_WITH_AES_128_GCM_SHA256": tls.TLS_RSA_WITH_AES_128_GCM_SHA256, "TLS_RSA_WITH_AES_256_GCM_SHA384": tls.TLS_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA": tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_RSA_WITH_RC4_128_SHA": tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, }
var curvePreferenceMap = map[string]tls.CurveID{ "CurveP256": tls.CurveP256, "CurveP384": tls.CurveP384, "CurveP521": tls.CurveP521, "X25519": tls.X25519, }
func GetTLSVersion(versionStr string) (uint16, bool) { version, ok := tlsVersionMap[strings.ToUpper(versionStr)]; return version, ok }
func GetCipherSuites(suiteNames []string) ([]uint16, error) { var suites []uint16; for _, name := range suiteNames { suiteID, ok := supportedCipherSuites[strings.ToUpper(name)]; if !ok { suiteIDAlt, okAlt := supportedCipherSuites["TLS_"+strings.ToUpper(name)]; if !okAlt { return nil, fmt.Errorf("unsupported cipher suite: %s", name)}; suiteID = suiteIDAlt}; suites = append(suites, suiteID) }; return suites, nil }
func GetCurvePreferences(curveNames []string) ([]tls.CurveID, error) { var curves []tls.CurveID; for _, name := range curveNames { curveID, ok := curvePreferenceMap[name]; if !ok { return nil, fmt.Errorf("unsupported curve preference: %s", name)}; curves = append(curves, curveID) }; return curves, nil }
