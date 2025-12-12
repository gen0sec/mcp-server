@echo off
REM Wrapper script for Windows to ensure dependencies are installed

setlocal

set "SCRIPT_DIR=%~dp0"
set "REQUIREMENTS_FILE=%SCRIPT_DIR%..\requirements.txt"
set "PYPROJECT_FILE=%SCRIPT_DIR%..\pyproject.toml"

REM Check if dependencies are installed
python -c "import mcp" 2>nul
if errorlevel 1 (
    REM Dependencies not installed, install them
    if exist "%REQUIREMENTS_FILE%" (
        echo Installing dependencies from requirements.txt...
        python -m pip install --user --quiet -r "%REQUIREMENTS_FILE%"
    ) else if exist "%PYPROJECT_FILE%" (
        echo Installing dependencies from pyproject.toml...
        python -m pip install --user --quiet "%SCRIPT_DIR%.."
    )
)

REM Run the main script with all arguments
python "%SCRIPT_DIR%main.py" %*
