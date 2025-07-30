#!/bin/bash
# NetSecureX Command Line Wrapper
# Simple bash script to run NetSecureX with the 'netsecx' command

# Set the NetSecureX directory
NETSECUREX_DIR="/Users/ssivared/NetSecureX"

# Change to the NetSecureX directory
cd "$NETSECUREX_DIR"

# Activate virtual environment and run the command
source "$NETSECUREX_DIR/venv/bin/activate"
python3 "$NETSECUREX_DIR/main.py" "$@"
