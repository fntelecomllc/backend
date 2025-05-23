#!/bin/bash

# --- Configuration ---
API_KEY="641f018600f939b24bb496ea87e6bb2edf1922457a058d5a3aa27a00c7073147" 
BASE_URL="http://localhost:8080/api/v1"

# Persona IDs from your http_personas.config.json
# Ensure these personas have different rateLimitDps values in http_personas.config.json
PERSONA_HTTP_FAST="chrome_win10_latest"  # e.g., rateLimitDps: 10.0 in http_personas.config.json
PERSONA_HTTP_SLOW="legacy_firefox_win7"   # e.g., rateLimitDps: 2.0 in http_personas.config.json

DOMAINS_HTTP_STREAM_LIST="httpbin.org/delay/1 httpbin.org/delay/0 httpbin.org/uuid httpbin.org/ip httpbin.org/user-agent httpbin.org/headers httpbin.org/status/404 httpbin.org/status/500 example.com nonexistentsite123456789.org"
DOMAIN_HTTP_QUERY_PARAMS=""
for DOMAIN in $DOMAINS_HTTP_STREAM_LIST; do
  # URL encode the domain/URL value
  ENCODED_DOMAIN=$(printf %s "$DOMAIN" | jq -s -R -r @uri)
  DOMAIN_HTTP_QUERY_PARAMS="${DOMAIN_HTTP_QUERY_PARAMS}&domain=${ENCODED_DOMAIN}"
done
DOMAIN_HTTP_QUERY_PARAMS_CLEAN="${DOMAIN_HTTP_QUERY_PARAMS#&}"


echo "===== STARTING HTTP STREAMING AND RATE LIMITING TEST ====="
echo "API Key (first 10 chars): ${API_KEY:0:10}..."
echo "Domains to test (raw): $DOMAINS_HTTP_STREAM_LIST"
echo "Query Params: $DOMAIN_HTTP_QUERY_PARAMS_CLEAN"
echo "-----------------------------------------------------"

perform_http_stream_request() {
    local test_name="$1"
    local curl_command_str="$2"

    echo ""
    echo "*** $test_name ***"
    echo "Command: $curl_command_str"
    echo "--- Output Start (Streaming - Ctrl+C to stop early if needed, or wait for 'Stream completed') ---"
    eval "$curl_command_str" 
    echo "" 
    echo "--- Output End for $test_name ---"
    echo "Please observe the rate of events above and check server logs for this test."
    echo "Press [Enter] to continue to next test..."
    read -r
}

# Test 1: HTTP Streaming with Server Default Rate Limit & HTTP Config
perform_http_stream_request \
    "Test 1: HTTP Streaming with Server Default Config (and its rate limit)" \
    "curl -N -H \"Authorization: Bearer $API_KEY\" \"${BASE_URL}/validate/http/stream?$DOMAIN_HTTP_QUERY_PARAMS_CLEAN\""

# Test 2: HTTP Streaming with Persona '$PERSONA_HTTP_FAST'
perform_http_stream_request \
    "Test 2: HTTP Streaming with Persona '$PERSONA_HTTP_FAST' (expecting its specific rate limit)" \
    "curl -N -H \"Authorization: Bearer $API_KEY\" \"${BASE_URL}/validate/http/stream?httpPersonaId=$PERSONA_HTTP_FAST&$DOMAIN_HTTP_QUERY_PARAMS_CLEAN\""

# Test 3: HTTP Streaming with Persona '$PERSONA_HTTP_SLOW'
perform_http_stream_request \
    "Test 3: HTTP Streaming with Persona '$PERSONA_HTTP_SLOW' (expecting its specific rate limit)" \
    "curl -N -H \"Authorization: Bearer $API_KEY\" \"${BASE_URL}/validate/http/stream?httpPersonaId=$PERSONA_HTTP_SLOW&$DOMAIN_HTTP_QUERY_PARAMS_CLEAN\""

echo "===== HTTP STREAMING AND RATE LIMITING TEST COMPLETE ====="
