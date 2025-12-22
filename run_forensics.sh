#!/bin/bash
# FIA Android Forensics Framework - Unix Launcher
# Run the forensic investigation agent

echo ""
echo "========================================"
echo "FIA Android Digital Forensics Framework"
echo "========================================"
echo ""

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not found. Please install Python 3.13+"
    exit 1
fi

# Check for virtual environment
if [ -d ".venv" ]; then
    echo "Activating virtual environment..."
    source .venv/bin/activate
fi

# Run the forensics agent
echo "Starting Forensic Investigation Agent..."
echo ""
python3 run_forensics.py
