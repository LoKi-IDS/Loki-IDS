#!/bin/bash
# Start IDS and setup iptables together (prevents internet loss)

set -e

cd "$(dirname "$0")/.."

echo "======================================================"
echo "  Starting Loki IDS with iptables Setup"
echo "======================================================"
echo ""

# Check if venv exists
if [ ! -d "Web-Interface/venv" ]; then
    echo "[!] Virtual environment not found!"
    echo "[*] Create it first: cd Web-Interface && env -i PATH=/usr/bin:/bin /usr/bin/python3 -m venv venv"
    exit 1
fi

# Step 1: Setup iptables
echo "[1/2] Setting up iptables..."
sudo ./Scripts/iptables_up.sh

echo ""
echo "⚠️  IMPORTANT: Starting IDS now to prevent internet loss..."
echo ""

# Step 2: Start IDS immediately
echo "[2/2] Starting IDS..."
echo "[*] IDS will run in this terminal"
echo "[*] Press Ctrl+C to stop (will also remove iptables rules)"
echo ""

# Trap Ctrl+C to cleanup
trap 'echo ""; echo "[*] Stopping IDS and cleaning up iptables..."; sudo ./Scripts/iptables_down.sh; exit' INT

# Start IDS
sudo Web-Interface/venv/bin/python3 Web-Interface/run_ids_with_integration.py

# Cleanup on exit
sudo ./Scripts/iptables_down.sh


