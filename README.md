# DomainFlow Backend Services

This directory contains the Go-based backend services for DomainFlow, including advanced DNS and HTTP validation engines and their controlling API. The system is designed for high-throughput, configurable, and stealthy domain intelligence operations.

## Prerequisites

-   Go (version 1.19 or later recommended).
-   Ensure your Go environment is set up with canonical import paths (e.g., `github.com/fntelecomllc/domainflow/backend/internal/...`).
-   Standard build tools (e.g., gcc for any CGO dependencies, though current core dependencies do not require it).
-   `jq` (optional, but highly recommended for command-line JSON parsing during API testing). Install via `sudo apt install jq`.

## Setup

1.  **Navigate to the `backend` directory:**
    ```bash
    cd backend
    ```

2.  **Module Path Configuration (Important: One-time setup for new clones/developers):**
    The Go module path defined in `backend/go.mod` should be:
    ```
    module github.com/fntelecomllc/domainflow/backend
    ```
    *(Note: Ensure consistency between your `go.mod` module path and the import paths used in `.go` files. If your `go.mod` in the `backend` directory is `module github.com/fntelecomllc/domainflow`, then internal import paths should be `github.com/fntelecomllc/domainflow/internal/...`.)*

    If your `go.mod` has a different module path, update it:
    ```bash
    # Run from the 'backend' directory
    go mod edit -module github.com/fntelecomllc/domainflow/backend
    ```
    Then, update import paths in your `.go` files if they were local (e.g., `"domainflow/internal/..."`):
    ```bash
    # Run from the 'backend' directory
    find . -name '*.go' -print0 | xargs -0 sed -i 's|import "domainflow/internal/|import "github.com/fntelecomllc/domainflow/backend/internal/|g'
    ```

3.  **Initialize/Tidy Go Modules:**
    This command downloads dependencies and cleans up the `go.mod` and `go.sum` files.
    ```bash
    # Run from the 'backend' directory
    go mod tidy
    ```

4.  **Configuration Files:**
    The server uses two primary JSON configuration files located within the `backend` directory:
    *   **`config.json`**: Defines main server settings (port, API key), default configurations for the DNS and HTTP validators (including default rate limits), and logging settings.
    *   **`dns_personas.config.json`**: An array of pre-defined DNS "personas," each specifying a complete DNS validation configuration.
    *   **`http_personas.config.json`**: An array of pre-defined HTTP "personas," each specifying a complete HTTP client configuration.

    Example files (`config.example.json`, `dns_personas.example.json`, `http_personas.example.json`) should be provided. Copy and customize them:
    ```bash
    # Run from the 'backend' directory
    cp config.example.json config.json
    cp dns_personas.example.json dns_personas.config.json 
    cp http_personas.example.json http_personas.config.json

    nano config.json         # CRITICAL: Set your server.apiKey. Adjust default validator settings.
    nano dns_personas.config.json # Define your DNS personas.
    nano http_personas.config.json # Define your HTTP personas.
    ```

    *   **API Key:** A strong, unique `server.apiKey` in `config.json` is essential for API security.
    *   **Environment Variable Overrides:** For enhanced security and flexibility, these can override `config.json` settings:
        *   `DOMAINFLOW_PORT`: Overrides the server port.
        *   `DOMAINFLOW_API_KEY`: Overrides `server.apiKey`. **This is the recommended method for production.**
           (e.g., `export DOMAINFLOW_API_KEY='your_very_secure_api_key_generated_here'`)

## Building the API Server

From the `backend` directory:
```bash
./scripts/build.sh


This compiles the Go application into an executable named domainflow-apiserver within the backend directory.

Running the API Server

Ensure the server is built and configuration files are correctly set up.

From the backend directory:

./scripts/run.sh


The server will start, typically on port 8080. Monitor startup logs for confirmation of loaded configurations and the API key.

API Endpoints

All endpoints under the /api/v1 prefix require Bearer Token authentication: Authorization: Bearer YOUR_API_KEY.

Health Check

GET /ping

Description: Checks if the server is running. No authentication required.

Response (200 OK): {"message":"pong","timestamp":"YYYY-MM-DDTHH:MM:SSZ"}

DNS Personas

GET /api/v1/dns/personas

Description: Lists all available, pre-defined DNS personas loaded from dns_personas.config.json.

Response (200 OK): application/json - Array of DNSPersonaListItem objects.

[
  { "id": "persona_id_1", "name": "Persona Name 1", "description": "Description..." },
  { "id": "persona_id_2", "name": "Persona Name 2", "description": "Description..." }
]


Errors: 500.

### DNS and HTTP Persona Management

These endpoints allow for dynamic creation, updating, and deletion of DNS and HTTP personas. Changes are persisted to `dns_personas.config.json` and `http_personas.config.json` respectively.

**DNS Personas:**

*   **`POST /api/v1/dns/personas`**: Creates a new DNS persona.
    *   Request Body: Full `DNSPersona` object (see `dns_personas.config.json` structure in "Configuration Details" section for fields like `id`, `name`, `description`, `config`).
    *   Response (201 Created): The created `DNSPersona` object.
    *   Errors: 400 (Invalid payload, ID empty, duplicate ID), 500 (Failed to save).
*   **`GET /api/v1/dns/personas`**: Lists all available DNS personas.
    *   Response (200 OK): Array of `DNSPersonaListItem` objects (id, name, description).
*   **`PUT /api/v1/dns/personas/{personaId}`**: Updates an existing DNS persona.
    *   Path Parameter: `personaId` (string, required).
    *   Request Body: Full `DNSPersona` object. The `id` in the body must match `personaId` in the path.
    *   Response (200 OK): The updated `DNSPersona` object.
    *   Errors: 400 (Invalid payload, ID mismatch), 404 (Not found), 500 (Failed to save).
*   **`DELETE /api/v1/dns/personas/{personaId}`**: Deletes a DNS persona.
    *   Path Parameter: `personaId` (string, required).
    *   Response (204 No Content).
    *   Errors: 404 (Not found), 500 (Failed to save).

**HTTP Personas:**

*   **`POST /api/v1/http/personas`**: Creates a new HTTP persona.
    *   Request Body: Full `HTTPPersona` object (see `http_personas.config.json` structure in "Configuration Details" section for fields).
    *   Response (201 Created): The created `HTTPPersona` object.
    *   Errors: 400 (Invalid payload, ID empty, duplicate ID), 500 (Failed to save).
*   **`GET /api/v1/http/personas`**: Lists all available HTTP personas.
    *   Response (200 OK): Array of `HTTPPersonaListItem` objects (id, name, description, userAgent).
*   **`PUT /api/v1/http/personas/{personaId}`**: Updates an existing HTTP persona.
    *   Path Parameter: `personaId` (string, required).
    *   Request Body: Full `HTTPPersona` object. The `id` in the body must match `personaId` in the path.
    *   Response (200 OK): The updated `HTTPPersona` object.
    *   Errors: 400 (Invalid payload, ID mismatch), 404 (Not found), 500 (Failed to save).
*   **`DELETE /api/v1/http/personas/{personaId}`**: Deletes an HTTP persona.
    *   Path Parameter: `personaId` (string, required).
    *   Response (204 No Content).
    *   Errors: 404 (Not found), 500 (Failed to save).

HTTP Personas

GET /api/v1/http/personas

Description: Lists all available, pre-defined HTTP personas loaded from http_personas.config.json.

Response (200 OK): application/json - Array of HTTPPersonaListItem objects.

[
  {
    "id": "chrome_win10_latest",
    "name": "Chrome Latest on Windows 10",
    "description": "Emulates a common user running up-to-date Google Chrome...",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  }
  // ... more personas ...
]


Errors: 500.

Campaign-Specific DNS Settings

Campaign DNS settings are managed via API and stored in-memory by the server.

PUT /api/v1/campaigns/{campaignId}/dns/settings

Description: Creates or updates the DNS validation settings for a specific campaign.

Path Parameter: campaignId (string, required).

Request Body (application/json):

{
  "rotationMode": "manual_sequential", 
  "selectedPersonaIds": ["persona_id_1", "persona_id_2"] 
}


rotationMode (string, required): See "DNS Rotation Modes" section below.

selectedPersonaIds ([]string, optional): Array of DNS Persona IDs. Required if rotationMode starts with "manual_".

Response (200 OK): The created/updated settings object.

Errors: 400, 500.

GET /api/v1/campaigns/{campaignId}/dns/settings

Description: Retrieves DNS settings for a specific campaign.

Path Parameter: campaignId (string, required).

Response (200 OK): The current settings object.

Errors: 400, 404, 500.

DNS Validation

POST /api/v1/validate/dns (Batch Processing)

Description: Validates domains and returns results in a single response.

Request Body (application/json):

{
  "domains": ["example.com", "another.org"],
  "campaignId": "campaign123",        // Optional
  "dnsPersonaId": "persona_for_this_run" // Optional
}


Response (200 OK): DNSValidationResponse.

Errors: 400, 500.

GET /api/v1/validate/dns/stream (Streaming Results - SSE)

Description: Validates domains and streams results using Server-Sent Events.

Query Parameters: domain (repeatable), campaignId (optional), dnsPersonaId (optional).

Example: curl -N -H "Auth..." "/api/v1/validate/dns/stream?domain=ex.com&dnsPersonaId=p1"

Response (text/event-stream): Stream of dns_result events, ending with a done event.

id: 1
event: dns_result
data: {"domain":"google.com","status":"Resolved",...}

event: done
data: Stream completed


Errors: 400, 500.

HTTP/S Validation

POST /api/v1/validate/http (Batch Processing)

Description: Validates domains via HTTP/S and returns results in a single response. Supports HTTP persona selection.

Request Body (application/json):

{
  "domains": ["example.com", "https://another.org"],
  "httpPersonaId": "persona_id_for_this_batch" // Optional
  // keywordSetId parameter removed. Use /api/v1/extract/keywords for keyword extraction.
}


Response (200 OK): HTTPValidationResponse.

Errors: 400, 500.

GET /api/v1/validate/http/stream (Streaming Results - SSE)

Description: Validates domains via HTTP/S and streams results using Server-Sent Events. Supports HTTP persona selection.

Query Parameters: domain (repeatable), httpPersonaId (optional).
// keywordSetId parameter removed. Use /api/v1/extract/keywords/stream for keyword extraction.

Example: curl -N -H "Auth..." "/api/v1/validate/http/stream?domain=httpbin.org/get&httpPersonaId=p_chrome"

Response (text/event-stream): Stream of http_result events, ending with a done event.

id: 1
event: http_result
data: {"domain":"httpbin.org/get","status":"OK",...}

event: done
data: HTTP Stream completed


Errors: 400, 500.

Server Default Configuration Management

Manage server's global default configurations (from config.json). Changes are persisted.

GET /api/v1/config/dns: Retrieves default DNS settings.

POST /api/v1/config/dns: Updates default DNS settings.

GET /api/v1/config/http: Retrieves default HTTP settings.

POST /api/v1/config/http: Updates default HTTP settings.

GET /api/v1/config/logging: Retrieves logging settings.

POST /api/v1/config/logging: Updates logging settings.

Configuration Details
Main Configuration (config.json)
server

port: string (e.g., "8080").

apiKey: string (Your secret API key).

logging

level: string ("DEBUG", "INFO", "WARN", "ERROR"). Default: "INFO".

dnsValidator (Server Default DNS Settings)

resolvers: []string (e.g., ["1.1.1.1:53", "https://cloudflare-dns.com/dns-query"]).

useSystemResolvers: bool. Default: false.

queryTimeoutSeconds: int. Default: 5.

maxDomainsPerRequest: int (For batch endpoint). Default: 100.

resolverStrategy: string ("random_rotation", "weighted_rotation", "sequential_failover"). Default: "random_rotation".

resolversWeighted: map[string]int (Optional).

resolversPreferredOrder: []string (Optional).

concurrentQueriesPerDomain: int (1 or 2). Default: 1.

queryDelayMinMs: int. Default: 0.

queryDelayMaxMs: int. Default: 50.

maxConcurrentGoroutines: int (Concurrency for batch/stream dispatch). Default: 10.

rateLimitDps: float64 (For /validate/dns/stream). Default: 10.0.

rateLimitBurst: int (For stream rate limiter). Default: 5.

httpValidator (Server Default HTTP Settings)

userAgents: []string.

defaultHeaders: map[string]string.

requestTimeoutSeconds: int. Default: 15.

maxRedirects: int. Default: 7.

maxDomainsPerRequest: int (For batch endpoint). Default: 50.

allowInsecureTLS: bool. Default: false.

maxConcurrentGoroutines: int. Default: 15.

rateLimitDps: float64 (For /validate/http/stream). Default: 5.0.

rateLimitBurst: int (For stream rate limiter). Default: 3.

DNS Personas (dns_personas.config.json)

An array of DNS Persona objects. Each persona defines a complete DNSValidatorConfigJSON structure (same fields as dnsValidator in config.json).

// Example entry in dns_personas.config.json
[
  {
    "id": "my_dns_persona",
    "name": "Custom DNS Persona Alpha",
    "description": "Specific DNS resolver set and strategy.",
    "config": { 
      "resolvers": ["1.0.0.1:53"],
      "queryTimeoutSeconds": 2,
      "resolverStrategy": "random_rotation", // This persona uses random_rotation on its own resolver list
      // ... all other DNSValidatorConfigJSON fields including rateLimitDps, rateLimitBurst ...
    }
  }
]

HTTP Personas (http_personas.config.json)

An array of HTTP Persona objects. Each defines settings for HTTP requests.

// Example entry in http_personas.config.json
[
  {
    "id": "my_http_persona",
    "name": "Custom HTTP Persona Beta",
    "description": "Specific User-Agent, headers, and TLS profile.",
    "userAgent": "MyCustomAgent/1.0",
    "headers": { "X-Custom-Header": "TestValue" },
    "headerOrder": ["User-Agent", "X-Custom-Header", "Accept"], // Optional
    "tlsClientHello": {
      "minVersion": "TLS12",
      "maxVersion": "TLS13",
      "cipherSuites": ["TLS_AES_128_GCM_SHA256", "..."],
      "curvePreferences": ["X25519", "CurveP256"]
    },
    "http2Settings": { "enabled": true },
    "cookieHandling": { "mode": "session" },
    "rateLimitDps": 7.0,   // Persona-specific DPS for HTTP streaming
    "rateLimitBurst": 3,
    "notes": "Internal notes."
  }
]

DNS Rotation Modes for Campaigns (rotationMode in Campaign DNS Settings)

all_sequential: Uses all loaded DNS personas sequentially per domain.

all_random_per_domain: Randomly picks from all loaded DNS personas for each domain.

all_random_per_request: Randomly picks one from all loaded DNS personas to use for the entire request batch/stream.

manual_sequential: Uses personas from the campaign's selectedPersonaIds list sequentially per domain.

manual_random_per_domain: Randomly picks from the campaign's selectedPersonaIds for each domain.

manual_random_per_request: Randomly picks one from the campaign's selectedPersonaIds to use for the entire request.
(For streaming, "per-request" modes determine the single persona (and its rate limit) used for the whole stream; "per-domain" modes select a persona per domain, but the stream's base rate limit comes from the initial determination (campaign default, direct persona, or server default).)

Testing with cURL

(Examples for Ping, Batch DNS/HTTP Validation, and Server Default Config updates are largely the same as before. Key new tests involve campaign settings and streaming.)

1. List DNS Personas:

curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:8080/api/v1/dns/personas


2. List HTTP Personas:

curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:8080/api/v1/http/personas


3. Set Campaign DNS Settings:

CAMPAIGN_ID="campaignAlpha"
API_KEY="YOUR_API_KEY"
curl -X PUT -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
     -d '{"rotationMode": "manual_sequential", "selectedPersonaIds": ["global_balanced_random", "global_stealth_sequential"]}' \
     "http://localhost:8080/api/v1/campaigns/$CAMPAIGN_ID/dns/settings"


4. Validate DNS using Campaign Settings (Streaming):

curl -N -H "Authorization: Bearer YOUR_API_KEY" \
  "http://localhost:8080/api/v1/validate/dns/stream?campaignId=campaignAlpha&domain=google.com&domain=cloudflare.com"


5. Validate HTTP using Specific Persona (Streaming):

curl -N -H "Authorization: Bearer YOUR_API_KEY" \
  "http://localhost:8080/api/v1/validate/http/stream?httpPersonaId=chrome_win10_latest&domain=httpbin.org/headers&domain=httpbin.org/user-agent"


### Keyword Extraction Endpoints

These endpoints are dedicated to fetching content from URLs and extracting keywords based on specified keyword sets. They support HTTP and DNS persona selection for the content fetching process.

**POST /api/v1/extract/keywords (Batch Keyword Extraction)**

Description: Fetches content for multiple URLs and extracts keywords.

Request Body (application/json):

```json
{
  "items": [
    {
      "url": "https://www.example.com/page1",
      "httpPersonaId": "persona_chrome_desktop", // Optional
      "dnsPersonaId": "persona_dns_google",    // Optional
      "keywordSetId": "contact_info_v1"        // Required
    },
    {
      "url": "http://another-example.org/about-us",
      "keywordSetId": "product_terms_v2"
    }
    // ... more items
  ]
}
```

*   `items`: Array of `KeywordExtractionRequestItem` objects.
    *   `url` (string, required): The URL to fetch content from.
    *   `httpPersonaId` (string, optional): ID of the HTTP Persona to use for fetching.
    *   `dnsPersonaId` (string, optional): ID of the DNS Persona to use for DNS resolution during fetching.
    *   `keywordSetId` (string, required): ID of the Keyword Set to use for extraction.

Response (200 OK): `BatchKeywordExtractionResponse`

```json
{
  "results": [
    {
      "url": "https://www.example.com/page1",
      "httpPersonaIdUsed": "persona_chrome_desktop",
      "dnsPersonaIdUsed": "persona_dns_google",
      "keywordSetIdUsed": "contact_info_v1",
      "matches": [
        { "matchedPattern": "email", "matchedText": "test@example.com", "category": "Email", "contexts": ["... contact us at test@example.com ..."] }
      ],
      "finalUrl": "https://www.example.com/page1",
      "statusCode": 200
    },
    {
      "url": "http://another-example.org/about-us",
      "keywordSetIdUsed": "product_terms_v2",
      "error": "Fetch error: request to http://another-example.org/about-us failed: net/http: request canceled (Client.Timeout exceeded while awaiting headers)",
      "statusCode": 0
    }
    // ... more results
  ]
}
```

*   `results`: Array of `KeywordExtractionAPIResult` objects.
    *   `url`: Original URL requested.
    *   `httpPersonaIdUsed`: Actual HTTP Persona ID used (or null if default/not specified).
    *   `dnsPersonaIdUsed`: Actual DNS Persona ID used (or null if default/not specified).
    *   `keywordSetIdUsed`: Keyword Set ID used.
    *   `matches`: Array of `keywordextractor.KeywordExtractionResult` containing found keywords (from `github.com/fntelecomllc/domainflow/backend/internal/keywordextractor`).
    *   `error`: Error message if fetching or extraction failed for this item.
    *   `finalUrl`: The URL after any redirects.
    *   `statusCode`: The HTTP status code from the fetch attempt.

Errors: 400 (Bad request, e.g., missing fields), 500 (Internal server error).

**GET /api/v1/extract/keywords/stream (Streaming Keyword Extraction)**

Description: Fetches content for a single URL and streams keyword extraction results using Server-Sent Events (SSE).

Query Parameters:

*   `url` (string, required): The URL to fetch and extract keywords from.
*   `keywordSetId` (string, required): The ID of the keyword set to use.
*   `httpPersonaId` (string, optional): ID of the HTTP Persona to use.
*   `dnsPersonaId` (string, optional): ID of the DNS Persona to use.

Example:
`curl -N -H "Authorization: Bearer YOUR_API_KEY" "http://localhost:8080/api/v1/extract/keywords/stream?url=https%3A%2F%2Fwww.example.com&keywordSetId=my_set_id&httpPersonaId=p_chrome"`

Response (text/event-stream):
Stream of events. A single `keyword_extraction_result` event is sent, followed by a `done` event. Errors during processing can also be sent as `error` events.

```
id: 1
event: keyword_extraction_result
data: {"url":"https://www.example.com","httpPersonaIdUsed":"p_chrome","keywordSetIdUsed":"my_set_id","matches":[...],"finalUrl":"https://www.example.com","statusCode":200}

event: done
data: Keyword extraction stream completed
```

Errors: 400 (Missing required parameters), 500.

Development

### Code Structure

The `internal/api` package has been refactored to organize its HTTP handlers into multiple files for better maintainability. Key files include:

*   `handlers.go`: Contains core DNS and HTTP validation handlers (without keyword extraction logic), server settings configuration handlers (`/config/*`), and their direct helper functions/structs.
*   `keyword_extraction_handlers.go`: Contains handlers for the new dedicated keyword extraction endpoints (`/extract/keywords` and `/extract/keywords/stream`).
*   `keyword_extraction_api_models.go`: Defines request/response structs for the keyword extraction API.
*   `handler_base.go`: Defines the main `APIHandler` struct (which holds shared dependencies like configuration, proxy manager, and now the content fetcher), its constructor `NewAPIHandler()`, and any package-level shared variables for handlers.
*   `handler_utils.go`: Contains common utility functions used by various handlers.
*   `ping_handler.go`: Contains the `PingHandler` for the `/ping` health check endpoint.
*   `persona_handlers.go`: Contains CRUD handlers for DNS and HTTP Personas.
*   `proxy_handlers.go`: Contains handlers for proxy management.
*   `campaign_handlers.go`: Contains handlers for campaign DNS settings.
*   `keyword_set_handlers.go`: Contains handlers for listing keyword sets and will be expanded for keyword set CRUD.

The `internal/contentfetcher` package now provides a `ContentFetcher` service used by keyword extraction handlers to retrieve web content with persona and proxy support.

This modular structure should make it easier to locate and modify specific pieces of API logic.

### Building & Running

Recompile: ./scripts/build.sh

Restart server: ./scripts/run.sh

Live Reloading (e.g., air):
Install: go install github.com/cosmtrek/air@latest
Create air.toml in backend directory (see example in previous README versions or customize).
Run: air (from backend directory).
