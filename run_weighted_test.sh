#!/bin/bash

# --- Configuration ---
API_KEY="641f018600f939b24bb496ea87e6bb2edf1922457a058d5a3aa27a00c7073147"
OUTPUT_FILE_RESOLVERS="dns_test_resolvers_weighted.txt" # Specific output file
OUTPUT_FILE_ERRORS="dns_test_errors_weighted.txt"     # Specific output file
OUTPUT_FILE_FULL_RESPONSES="dns_test_full_responses_weighted.txt" # Specific output file
REQUEST_COUNT=100 # For statistical relevance of weights
DOMAIN_TO_TEST="google.com" # A reliable domain
DOMAINS_JSON="{\"domains\": [\"$DOMAIN_TO_TEST\"]}"


# --- Ensure jq is installed ---
if ! command -v jq &> /dev/null; then
    echo "jq is not installed. Please install it first (e.g., sudo apt install jq)."
    exit 1
fi

# --- Clear previous results ---
> "$OUTPUT_FILE_RESOLVERS"
> "$OUTPUT_FILE_ERRORS"
> "$OUTPUT_FILE_FULL_RESPONSES"

echo "Starting Test 2.1: Weighted Rotation DNS Validation"
echo "Sending $REQUEST_COUNT DNS validation requests for: $DOMAINS_JSON"
echo "API Key being used (first 10 chars): ${API_KEY:0:10}..."
echo "-----------------------------------------------------"


for i in $(seq 1 $REQUEST_COUNT)
do
  # echo "Sending request $i..." # Can be too verbose for many requests
  response=$(curl -s -X POST \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "$DOMAINS_JSON" \
    http://localhost:8080/api/v1/validate/dns)

  echo "Full response for request $i:" >> "$OUTPUT_FILE_FULL_RESPONSES"
  echo "$response" >> "$OUTPUT_FILE_FULL_RESPONSES"
  echo "" >> "$OUTPUT_FILE_FULL_RESPONSES" 

  if ! echo "$response" | jq -e .results &> /dev/null; then
    echo "Request $i: Received non-JSON or unexpected response: $response" >> "$OUTPUT_FILE_ERRORS"
    if [[ "$response" == "Invalid API Key" ]]; then
         echo "Request $i: FAILED DUE TO INVALID API KEY. Check server config and script API_KEY." >> "$OUTPUT_FILE_ERRORS"
    fi
    continue 
  fi
  
  resolver=$(echo "$response" | jq -r 'if .results and (.results | length > 0) then .results[0].resolver else "" end')
  status=$(echo "$response" | jq -r 'if .results and (.results | length > 0) then .results[0].status else "" end')
  error_msg=$(echo "$response" | jq -r 'if .results and (.results | length > 0) then .results[0].error else "" end')

  if [ "$status" == "Resolved" ]; then
    if [ -n "$resolver" ]; then
      echo "$resolver" >> "$OUTPUT_FILE_RESOLVERS"
    else
      echo "Request $i resolved but resolver field missing. Full response: $response" >> "$OUTPUT_FILE_ERRORS"
    fi
  elif [ "$status" == "Not Found" ]; then
    echo "Request $i: Domain $DOMAIN_TO_TEST - Status: Not Found. Resolver: $resolver. Error: $error_msg" >> "$OUTPUT_FILE_ERRORS"
  elif [ "$status" == "Error" ]; then
    echo "Request $i: Domain $DOMAIN_TO_TEST - Status: Error. Resolver: $resolver. Error: $error_msg" >> "$OUTPUT_FILE_ERRORS"
  elif [ -z "$status" ]; then 
    echo "Request $i: Status field empty or missing. Full response: $response" >> "$OUTPUT_FILE_ERRORS"
  else 
    echo "Request $i: Domain $DOMAIN_TO_TEST - Status: $status. Resolver: $resolver. Error: $error_msg" >> "$OUTPUT_FILE_ERRORS"
  fi
  
  if (( i % 10 == 0 )); then
    echo "Completed $i requests..."
  fi
done

echo "-----------------------------------------------------"
echo "Finished $REQUEST_COUNT requests."
echo ""
echo "Resolver distribution (from successful 'Resolved' statuses) for WEIGHTED ROTATION:"
if [ -s "$OUTPUT_FILE_RESOLVERS" ]; then
  sort "$OUTPUT_FILE_RESOLVERS" | uniq -c | sort -nr
else
  echo "No successful 'Resolved' statuses recorded in $OUTPUT_FILE_RESOLVERS."
fi
echo ""
echo "Check '$OUTPUT_FILE_ERRORS' for any non-Resolved statuses or errors."
echo "Full JSON responses are in '$OUTPUT_FILE_FULL_RESPONSES'."
