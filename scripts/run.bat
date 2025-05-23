@echo off
echo Starting DomainFlow Go API server...

REM Get the directory of the script itself
set "SCRIPT_DIR=%~dp0"
REM Go to the backend root directory
pushd "%SCRIPT_DIR%..\"

echo Changing directory to: %CD%

REM Set environment variables (examples, override as needed)
REM set DOMAINFLOW_PORT=8080
REM set DOMAINFLOW_API_KEY=your-super-secret-api-key

REM Check if config.json exists, if not, copy from example
if not exist "config.json" (
    if exist "config.example.json" (
        echo config.json not found. Copying from config.example.json...
        copy config.example.json config.json
        if errorlevel 1 (
            echo Error: Failed to copy config.example.json to config.json.
            REM Decide if you want to exit or continue with potential defaults from code
            REM popd
            REM exit /b 1
        )
    ) else (
        echo Warning: config.json and config.example.json not found. Server will use hardcoded defaults or environment variables.
    )
)

REM Check if keywords.config.json exists, if not, copy from example
if not exist "keywords.config.json" (
    if exist "keywords.example.config.json" (
        echo keywords.config.json not found. Copying from keywords.example.config.json...
        copy keywords.example.config.json keywords.config.json
        if errorlevel 1 (
            echo Error: Failed to copy keywords.example.config.json to keywords.config.json.
        )
    ) else (
        echo Warning: keywords.config.json and keywords.example.config.json not found. Keyword extraction may not function.
    )
)

REM Run the built executable
REM Assumes domainflow-apiserver.exe is in the current directory (backend/)
if exist ".\domainflow-apiserver.exe" (
    echo Executing .\domainflow-apiserver.exe...
    .\domainflow-apiserver.exe
) else (
    echo Error: domainflow-apiserver.exe not found in %CD%.
    echo Build it first by running: "%SCRIPT_DIR%build.bat"
    popd
    exit /b 1
)

popd
echo Run script finished.
