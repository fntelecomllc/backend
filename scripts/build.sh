#!/bin/bash
echo "Building DomainFlow Go API server..."

# Get the directory of the script itself
SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# Go to the backend root directory (parent of scripts directory)
BACKEND_ROOT_DIR="$(dirname "${SCRIPT_DIR}")"

echo "Changing directory to: ${BACKEND_ROOT_DIR}"
cd "${BACKEND_ROOT_DIR}" || { echo "Failed to cd to backend root: ${BACKEND_ROOT_DIR}"; exit 1; }


# Tidying up modules
echo "Running go mod tidy..."
go mod tidy
if [ $? -ne 0 ]; then
  echo "go mod tidy failed."
  exit 1
fi

# Optional: vendor dependencies
# echo "Running go mod vendor..."
# go mod vendor
# if [ $? -ne 0 ]; then
#   echo "go mod vendor failed."
#   exit 1
# fi

# Build the application
# The output binary will be in the current directory (backend/) named 'domainflow-apiserver'
echo "Building for Linux amd64..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o domainflow-apiserver ./cmd/apiserver/main.go

if [ $? -eq 0 ]; then
  echo "Build successful. Executable: ${BACKEND_ROOT_DIR}/domainflow-apiserver"
  ls -l "${BACKEND_ROOT_DIR}/domainflow-apiserver"
else
  echo "Build failed."
  exit 1
fi

