@echo off
echo Running Keyword Extractor Test...

REM Get the directory of this script
set "SCRIPT_DIR=%~dp0"

REM Navigate to the backend root directory (parent of scripts)
pushd "%SCRIPT_DIR%..\"

echo Current directory: %CD%

set TEST_RUNNER_SRC=./cmd/apiserver/keyword_test_runner.go
set TEST_RUNNER_EXE=keyword_test_runner.exe

echo Building Keyword Extractor test runner...
go build -o %TEST_RUNNER_EXE% %TEST_RUNNER_SRC%

if errorlevel 1 (
    echo Build failed for test runner.
    popd
    exit /b 1
)

echo Running Keyword Extractor test runner...
.\%TEST_RUNNER_EXE%

echo Cleaning up...
del %TEST_RUNNER_EXE%

popd
echo Keyword Extractor Test Finished.
