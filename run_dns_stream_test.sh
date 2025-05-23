#!/bin/bash

# --- Configuration ---
API_KEY="641f018600f939b24bb496ea87e6bb2edf1922457a058d5a3aa27a00c7073147" # MAKE SURE THIS IS YOUR SERVER'S API KEY
BASE_URL="http://localhost:8080/api/v1"

# Persona IDs (ensure these exist in your dns_personas.config.json with different rateLimitDps)
PERSONA_FAST_RATE="global_balanced_random"  # Expects higher DPS in dns_personas.config.json
PERSONA_SLOW_RATE="global_stealth_sequential" # Expects lower DPS in dns_personas.config.json

DOMAINS_LIST="google.com cloudflare.com github.com bing.com yahoo.com wikipedia.org amazon.com apple.com microsoft.com baidu.com"
DOMAIN_QUERY_PARAMS=""
for DOMAIN in $DOMAINS_LIST; do
  DOMAIN_QUERY_PARAMS="${DOMAIN_QUERY_PARAMS}&domain=${DOMAIN}"
done
# Remove leading '&'
DOMAIN_QUERY_PARAMS_CLEAN="${DOMAIN_QUERY_PARAMS#&}"


echo "===== STARTING DNS STREAMING AND RATE LIMITING TEST ====="
echo "API Key (first 10 chars): ${API_KEY:0:10}..."
echo "Domains to test: $DOMAINS_LIST"
echo "-----------------------------------------------------"

# Function to make a standard streaming curl request and display output
# Usage: perform_stream_request "Test Name" "Full Curl Command String"
perform_stream_request() {
    local test_name="$1"
    local curl_command_str="$2"

    echo ""
    echo "*** $test_name ***"
    echo "Command: $curl_command_str"
    echo "--- Output Start (Streaming - Ctrl+C to stop early if needed, or wait for 'Stream completed') ---"
    eval "$curl_command_str" # Execute the command string
    echo "" # Newline after curl output
    echo "--- Output End for $test_name ---"
    echo "Please observe the rate of events above and check server logs for this test."
    echo "Press [Enter] to continue to next test..."
    read -r
}


# Test 1: Streaming with Server Default Rate Limit
perform_stream_request \
    "Test 1: Streaming with Server Default DNS Config (and its rate limit)" \
    "curl -N -H \"Authorization: Bearer $API_KEY\" \"${BASE_URL}/validate/dns/stream?$DOMAIN_QUERY_PARAMS_CLEAN\""

# Test 2: Streaming with a specific Persona (Fast Rate Limit)
perform_stream_request \
    "Test 2: Streaming with Persona '$PERSONA_FAST_RATE' (expecting its specific rate limit)" \
    "curl -N -H \"Authorization: Bearer $API_KEY\" \"${BASE_URL}/validate/dns/stream?dnsPersonaId=$PERSONA_FAST_RATE&$DOMAIN_QUERY_PARAMS_CLEAN\""

# Test 3: Streaming with a specific Persona (Slow Rate Limit)
perform_stream_request \
    "Test 3: Streaming with Persona '$PERSONA_SLOW_RATE' (expecting its specific rate limit)" \
    "curl -N -H \"Authorization: Bearer $API_KEY\" \"${BASE_URL}/validate/dns/stream?dnsPersonaId=$PERSONA_SLOW_RATE&$DOMAIN_QUERY_PARAMS_CLEAN\""


# Test 4: Streaming with Campaign Settings
CAMPAIGN_ID_STREAM_TEST="campaignStreamTest01"
echo ""
echo "*** Test 4: Streaming with Campaign '$CAMPAIGN_ID_STREAM_TEST' ***"
echo "Setting campaign to use persona '$PERSONA_SLOW_RATE' with 'manual_random_per_request' mode."
# Using manual_random_per_request with a single selected persona ensures that persona is chosen.
campaign_settings_payload=$(cat <<EOF
{
  "rotationMode": "manual_random_per_request", 
  "selectedPersonaIds": ["$PERSONA_SLOW_RATE"] 
}
EOF
)

echo "Applying campaign settings via PUT..."
echo "Payload for PUT:"
echo "$campaign_settings_payload" | jq .
echo "---"

# Capture full output (stdout and stderr) from the PUT request
# -v makes curl verbose and writes to stderr
put_response_verbose=$(curl -s -v -X PUT \
     -H "Authorization: Bearer $API_KEY" \
     -H "Content-Type: application/json" \
     -d "$campaign_settings_payload" \
     "${BASE_URL}/campaigns/$CAMPAIGN_ID_STREAM_TEST/dns/settings" 2>&1) # Redirect stderr to stdout to capture it

echo "--- Full Verbose Output from PUT request (including headers and potential errors) ---"
echo "$put_response_verbose"
echo "--- End of PUT Verbose Output ---"
echo ""

# Try to parse the body of the PUT response as JSON, if possible
# Extracting just the body part from verbose output is tricky, so let's assume if it's not a 2xx, it failed.
# A more robust way would be to use -w "%{http_code}" with -o /dev/null and then a separate curl for body.
# For now, we rely on observing the verbose output. If it contains a JSON body, jq will parse it.
# If it's an HTML error page (like 400), jq will fail.

body_candidate=$(echo "$put_response_verbose" | awk '/^{/,/}^/{print}; /^\\[/{print; while(getline && !/^]/){print}; print "]" }')
if echo "$body_candidate" | jq -e . &> /dev/null; then
    echo "Parsed JSON Body from PUT response:"
    echo "$body_candidate" | jq .
else
    echo "Could not parse JSON body from PUT response. The response might be an error page or not JSON."
    echo "If the PUT failed, the subsequent stream test for this campaign might use server defaults."
fi
echo ""


perform_stream_request \
    "Test 4 Stream Validation (Campaign: '$CAMPAIGN_ID_STREAM_TEST')" \
    "curl -N -H \"Authorization: Bearer $API_KEY\" \"${BASE_URL}/validate/dns/stream?campaignId=$CAMPAIGN_ID_STREAM_TEST&$DOMAIN_QUERY_PARAMS_CLEAN\""


echo "===== DNS STREAMING AND RATE LIMITING TEST COMPLETE ====="
echo "Please check server logs for detailed persona selection messages for each validation request."
