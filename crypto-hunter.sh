#!/bin/bash
# Crypto Hunter launcher script

# Directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Default virtual environment path
VENV_PATH="${SCRIPT_DIR}/venv"

# Check if the virtual environment exists
if [ ! -d "${VENV_PATH}" ]; then
    echo "Virtual environment not found at ${VENV_PATH}"
    echo "Running installation script..."
    python "${SCRIPT_DIR}/install.py"
    
    if [ $? -ne 0 ]; then
        echo "Installation failed. Please run install.py manually."
        exit 1
    fi
fi

# Activate virtual environment
source "${VENV_PATH}/bin/activate"

# Run Crypto Hunter with all arguments passed to this script
python "${SCRIPT_DIR}/main.py" "$@"

# Deactivate virtual environment
deactivate
