#!/bin/bash
# Enhanced Crypto Hunter Startup Script

echo "🧩 Enhanced Crypto Hunter"
echo "========================"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/upgrade requirements
echo "Installing requirements..."
pip install -r requirements_enhanced.txt

# Run the application
echo "Starting Enhanced Crypto Hunter..."
python main.py "$@"
