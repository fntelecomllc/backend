#!/bin/bash

# --- Configuration ---
API_KEY="641f018600f939b24bb496ea87e6bb2edf1922457a058d5a3aa27a00c7073147" # Ensure this is your server's API key
BASE_URL="http://localhost:8080/api/v1"

# Persona ID from your http_personas.config.json (e.g., the first one)
# Choose one that has some distinctive headers or User-Agent
TEST_PERSONA_ID="chrome_win10_latest" 

# Domains that reflect headers and user-agent back
# httpbin.org is excellent for this.
DOMAINS_TO_TEST_HTTP="[\"httpbin.org/headers\", \"httpbin.org/user-agent\", \"httpbin.org/get\"]"

echo "===== STARTING HTTP PERSONA VALIDATION TEST (BATCH) ====="
echo "API Key (first 10 chars): ${API_KEY:0:10}..."
echo "Using HTTP Persona ID: $TEST_PERSONA_ID"
echo "Testing domains: $DOMAINS_TO_TEST_HTTP"
echo "-----------------------------------------------------"

# Function to make a pretty printed curl request
make_curl_request() {
    local method="$1"
    local endpoint="$2"
    local data="$3"
    
    echo ""
    echo "--- Sending $method $BASE_URL$endpoint ---"
    if [ -n "$data" ]; then
        echo "Request Body:"
        echo "$data" | jq .
        echo "--- Response ---"
        curl -s -X "$method" \
             -H "Authorization: Bearer $API_KEY" \
             -H "Content-Type: application/json" \
             -d "$data" \
             "$BASE_URL$endpoint" | jq .
    else
        curl -s -X "$method" \
             -H "Authorization: Bearer $API_KEY" \
             "$BASE_URL$endpoint" | jq .
    fi
    echo "--- End $method $BASE_URL$endpoint ---"
    echo ""
}

# Test 1: List available HTTP Personas
echo "*** Test 1: Listing available HTTP Personas ***"
make_curl_request "GET" "/http/personas"
echo "Press [Enter] to continue..."
read -r

# Test 2: HTTP Validation using a specific Persona
echo "*** Test 2: HTTP Validation using Persona '$TEST_PERSONA_ID' ***"
http_validate_payload=$(cat <<EOF
{
  "domains": $DOMAINS_TO_TEST_HTTP,
  "httpPersonaId": "$TEST_PERSONA_ID"
}
EOF
)
make_curl_request "POST" "/validate/http" "$http_validate_payload"
echo "--- (Examine the 'headers' and 'user-agent' output from httpbin.org in the response above) ---"
echo "--- (Check server logs for 'API HTTP Batch: Using HTTP Persona ID: ...' message) ---"
echo "Press [Enter] to continue..."
read -r

# Test 3: HTTP Validation using Server Default HTTP Config
echo "*** Test 3: HTTP Validation using Server Default HTTP Config ***"
http_validate_payload_default=$(cat <<EOF
{
  "domains": $DOMAINS_TO_TEST_HTTP
}
EOF
)
make_curl_request "POST" "/validate/http" "$http_validate_payload_default"
echo "--- (Compare headers/UA with Test 2. It should use defaults from config.json) ---"
echo "--- (Check server logs for 'API HTTP Batch: No specific persona. Using server default...' message) ---"


echo "===== HTTP PERSONA VALIDATION TEST (BATCH) COMPLETE ====="
