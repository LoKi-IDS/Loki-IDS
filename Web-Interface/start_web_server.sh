#!/bin/bash
# Start the Loki IDS Web Interface server

cd "$(dirname "$0")"

echo "======================================================"
echo "    Starting Loki IDS Web Interface"
echo "======================================================"

# Check if virtual environment exists, create if needed
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    env -i PATH=/usr/bin:/bin /usr/bin/python3 -m venv venv
    echo "[*] Installing dependencies..."
    venv/bin/pip install -q -r requirements.txt
fi

# Install/update dependencies (skip netfilterqueue - not needed for web interface)
echo "[*] Checking dependencies..."
venv/bin/pip install -q -r requirements.txt || {
    echo "[!] Warning: Some dependencies failed to install"
    echo "[*] Continuing anyway (web interface may still work)"
}

# Start the server
echo "[*] Starting FastAPI server..."
echo "[*] Dashboard will be available at: http://localhost:8080"
echo "[*] API documentation at: http://localhost:8080/docs"
echo ""

venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8080 --reload

