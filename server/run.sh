#!/bin/bash
# Wrapper script to ensure dependencies are installed before running the server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQUIREMENTS_FILE="$SCRIPT_DIR/../requirements.txt"
PYPROJECT_FILE="$SCRIPT_DIR/../pyproject.toml"

# Check if we're in a virtual environment or if dependencies are installed
if ! python3 -c "import mcp" 2>/dev/null; then
    # Dependencies not installed, install them
    if [ -f "$REQUIREMENTS_FILE" ]; then
        echo "Installing dependencies from requirements.txt..." >&2
        python3 -m pip install --user --quiet -r "$REQUIREMENTS_FILE"
    elif [ -f "$PYPROJECT_FILE" ]; then
        echo "Installing dependencies from pyproject.toml..." >&2
        python3 -m pip install --user --quiet "$SCRIPT_DIR/.."
    fi
fi

# Run the main script with all arguments
exec python3 "$SCRIPT_DIR/main.py" "$@"
