#!/bin/bash

# Test script for DNS Validation Streaming and Rate Limiting

API_KEY_VALUE="641f018600f939b24bb496ea87e6bb2edf1922457a058d5a3aa27a00c7073147" # Use your actual API key
BASE_URL="http://localhost:8080/api/v1/validate/dns/stream"

DOMAINS_TO_TEST=(
    "google.com"
    "cloudflare.com"
    "github.com"
    "wikipedia.org"
    "nonexistentdomain123abcxyz.com" # Should fail
    "example.com"
    "iana.org"
    "ietf.org"
    "dns.google"
    "one.one.one.one"
)

echo "===== STARTING DNS STREAMING AND RATE LIMITING TEST ====="
echo "API Key (first 10 chars): ${API_KEY_VALUE:0:10}..."
echo "Domains to test (raw): ${DOMAINS_TO_TEST[@]}"

QUERY_PARAMS=""
for DOMAIN in "${DOMAINS_TO_TEST[@]}"; do
    # URL encode the domain
    ENCODED_DOMAIN=$(printf %s "$DOMAIN" | jq -s -R -r @uri)
    if [ -z "$QUERY_PARAMS" ]; then
        QUERY_PARAMS="domain=$ENCODED_DOMAIN"
    else
        QUERY_PARAMS="$QUERY_PARAMS&domain=$ENCODED_DOMAIN"
    fi
done
echo "Query Params: $QUERY_PARAMS"
echo "-----------------------------------------------------"
echo

# --- Test 1: DNS Streaming with Server Default Config (and its rate limit) ---
echo "*** Test 1: DNS Streaming with Server Default Config (and its rate limit) ***"
CMD1="curl -N -H \"Authorization: Bearer $API_KEY_VALUE\" \"$BASE_URL?$QUERY_PARAMS\""
echo "Command: $CMD1"
echo "--- Output Start (Streaming - Ctrl+C to stop early if needed, or wait for 'Stream completed') ---"
eval $CMD1
echo
echo "--- Output End for Test 1 ---"
echo "Please observe the rate of events above and check server logs for this test."
read -p "Press [Enter] to continue to next test..."
echo

# --- Test 2: DNS Streaming with a specific DNS Persona ---
# Replace 'YOUR_DNS_PERSONA_ID' with an actual ID from your dns_personas.config.json
# For example, 'global_balanced_random' or one that has specific rate limits if you defined them.
DNS_PERSONA_ID="global_balanced_random" # Example, ensure this persona exists
echo "*** Test 2: DNS Streaming with Persona '$DNS_PERSONA_ID' (expecting its specific rate limit) ***"
CMD2="curl -N -H \"Authorization: Bearer $API_KEY_VALUE\" \"$BASE_URL?dnsPersonaId=$DNS_PERSONA_ID&$QUERY_PARAMS\""
echo "Command: $CMD2"
echo "--- Output Start (Streaming - Ctrl+C to stop early if needed, or wait for 'Stream completed') ---"
eval $CMD2
echo
echo "--- Output End for Test 2 ---"
echo "Please observe the rate of events above and check server logs for this test."
read -p "Press [Enter] to continue to next test..."
echo


# --- Test 3: DNS Streaming with another DNS Persona (e.g., one with different rate limits or resolver strategy) ---
DNS_PERSONA_ID_ALT="global_stealth_sequential" # Example, ensure this persona exists and is unique
echo "*** Test 3: DNS Streaming with Persona '$DNS_PERSONA_ID_ALT' ***"
CMD3="curl -N -H \"Authorization: Bearer $API_KEY_VALUE\" \"$BASE_URL?dnsPersonaId=$DNS_PERSONA_ID_ALT&$QUERY_PARAMS\""
echo "Command: $CMD3"
echo "--- Output Start (Streaming - Ctrl+C to stop early if needed, or wait for 'Stream completed') ---"
eval $CMD3
echo
echo "--- Output End for Test 3 ---"
echo "Please observe the rate of events above and check server logs for this test."
# read -p "Press [Enter] to continue to next test..." # Commented out for last test
echo


echo "===== DNS STREAMING AND RATE LIMITING TEST COMPLETE ====="
