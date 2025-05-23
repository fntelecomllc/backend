@echo off
echo Building DomainFlow Go API server...

REM Get the directory of the script itself
set "SCRIPT_DIR=%~dp0"
REM Go to the backend root directory (parent of scripts directory)
pushd "%SCRIPT_DIR%..\"

echo Changing directory to: %CD%

REM Tidying up modules
echo Running go mod tidy...
go mod tidy
if %errorlevel% neq 0 (
  echo go mod tidy failed.
  popd
  exit /b 1
)

REM Build the application
REM The output binary will be in the current directory (backend/) named 'domainflow-apiserver.exe'
echo Building for Windows...
go build -ldflags="-s -w" -o domainflow-apiserver.exe ./cmd/apiserver/main.go

if %errorlevel% equ 0 (
  echo Build successful. Executable: %CD%\domainflow-apiserver.exe
  dir domainflow-apiserver.exe
) else (
  echo Build failed.
  popd
  exit /b 1
)

popd
echo Build script finished.
