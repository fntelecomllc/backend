#!/bin/bash
echo "Starting DomainFlow Go API server..."

# Get the directory of the script itself
SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# Go to the backend root directory
BACKEND_ROOT_DIR="$(dirname "${SCRIPT_DIR}")"

echo "Changing directory to: ${BACKEND_ROOT_DIR}"
cd "${BACKEND_ROOT_DIR}" || { echo "Failed to cd to backend root: ${BACKEND_ROOT_DIR}"; exit 1; }


# Set environment variables (examples, override as needed)
# export DOMAINFLOW_PORT="8080"
# export DOMAINFLOW_API_KEY="your-super-secret-api-key" # Strongly recommend setting this externally

# Check if config.json exists, if not, copy from example
if [ ! -f "config.json" ]; then
    if [ -f "config.example.json" ]; then
        echo "config.json not found. Copying from config.example.json..."
        cp config.example.json config.json
        if [ $? -ne 0 ]; then
            echo "Error: Failed to copy config.example.json to config.json."
            # Decide if you want to exit or continue with potential defaults from code
            # exit 1 
        fi
    else
        echo "Warning: config.json and config.example.json not found. Server will use hardcoded defaults or environment variables."
    fi
fi

# Check if keywords.config.json exists, if not, copy from example
if [ ! -f "keywords.config.json" ]; then
    if [ -f "keywords.example.config.json" ]; then
        echo "keywords.config.json not found. Copying from keywords.example.config.json..."
        cp keywords.example.config.json keywords.config.json
        if [ $? -ne 0 ]; then
            echo "Error: Failed to copy keywords.example.config.json to keywords.config.json."
        fi
    else
        echo "Warning: keywords.config.json and keywords.example.config.json not found. Keyword extraction may not function."
    fi
fi


# Run the built executable
# Assumes domainflow-apiserver is in the current directory (backend/)
if [ -f "./domainflow-apiserver" ]; then
    echo "Executing ./domainflow-apiserver..."
    # Use exec to replace the shell process with the server process if desired,
    # or just run it directly to keep the shell script as the parent.
    ./domainflow-apiserver
else
    echo "Error: domainflow-apiserver not found in ${BACKEND_ROOT_DIR}."
    echo "Build it first by running: ${SCRIPT_DIR}/build.sh"
    exit 1
fi
