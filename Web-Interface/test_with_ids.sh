#!/bin/bash
# Interactive test script for testing with IDS

set -e

echo "======================================================"
echo "  Loki IDS - Complete Testing Script"
echo "======================================================"
echo ""

# Check prerequisites
echo "[*] Checking prerequisites..."

if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 not found"
    exit 1
fi

if [ "$EUID" -ne 0 ] && ! sudo -n true 2>/dev/null; then
    echo "[!] This script requires sudo access for IDS testing"
    echo "[*] You'll be prompted for sudo password"
fi

echo "[✓] Prerequisites OK"
echo ""

# Step 1: Check Web Interface
echo "======================================================"
echo "  Step 1: Web Interface"
echo "======================================================"
echo ""

if ! curl -s http://localhost:8080/api/system/health > /dev/null; then
    echo "[!] Web interface is not running!"
    echo ""
    echo "Start it in a separate terminal:"
    echo "  cd /home/zaher/Loki-IDS/Web-Interface"
    echo "  venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8080"
    echo ""
    read -p "Press Enter when web interface is running..."
else
    echo "[✓] Web interface is running"
fi

# Step 2: Add test signature
echo ""
echo "======================================================"
echo "  Step 2: Add Test Signature"
echo "======================================================"
echo ""

echo "Adding test signature via API..."
curl -s -X POST http://localhost:8080/api/signatures \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Test Signature",
        "pattern": "TEST_PATTERN_123",
        "action": "alert",
        "description": "Test signature for IDS testing"
    }' > /dev/null && echo "[✓] Test signature added" || echo "[!] Failed to add signature"

# Step 3: Setup iptables
echo ""
echo "======================================================"
echo "  Step 3: Setup iptables"
echo "======================================================"
echo ""

echo ""
echo "⚠️  IMPORTANT: iptables will intercept ALL traffic!"
echo "⚠️  You MUST start IDS immediately after, or you'll lose internet!"
echo ""
read -p "Setup iptables and start IDS together? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cd /home/zaher/Loki-IDS
    
    # Use combined script that does both
    echo "[*] Using combined script (iptables + IDS)..."
    echo "[*] This prevents internet loss"
    echo ""
    sudo ./Scripts/start_ids_with_iptables.sh
else
    echo ""
    echo "[*] Setting up iptables only..."
    echo "⚠️  WARNING: Start IDS IMMEDIATELY or you'll lose internet!"
    echo ""
    read -p "Continue with iptables setup? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cd /home/zaher/Loki-IDS
        sudo ./Scripts/iptables_up.sh
        echo ""
        echo "⚠️  CRITICAL: Start IDS NOW!"
        echo "   sudo ./Web-Interface/start_ids.sh"
        echo "   Or: sudo Web-Interface/venv/bin/python3 Web-Interface/run_ids_with_integration.py"
    else
        echo "[*] Skipping iptables setup"
    fi
fi

