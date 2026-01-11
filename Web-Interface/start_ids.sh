#!/bin/bash
# Start IDS with database integration (uses venv Python)

cd "$(dirname "$0")/.."

# Check if venv exists
if [ ! -d "Web-Interface/venv" ]; then
    echo "[!] Virtual environment not found!"
    echo "[*] Create it first: cd Web-Interface && env -i PATH=/usr/bin:/bin /usr/bin/python3 -m venv venv"
    exit 1
fi

# Check if IDS dependencies are installed
echo "[*] Checking IDS dependencies..."
if ! Web-Interface/venv/bin/python3 -c "import netfilterqueue" 2>/dev/null; then
    echo "[!] netfilterqueue not found in venv"
    echo "[*] Installing IDS dependencies..."
    echo "[*] Note: This requires system libraries:"
    echo "    sudo apt-get install python3-dev libnetfilter-queue-dev libnfnetlink-dev libpcap-dev"
    echo ""
    
    # Try to install
    if [ -f "Web-Interface/requirements-ids.txt" ]; then
        Web-Interface/venv/bin/pip install -q -r Web-Interface/requirements-ids.txt || {
            echo "[!] Failed to install IDS dependencies"
            echo "[!] Please install system libraries first:"
            echo "    sudo apt-get install python3-dev libnetfilter-queue-dev libnfnetlink-dev libpcap-dev"
            echo "    Then run: Web-Interface/venv/bin/pip install -r Web-Interface/requirements-ids.txt"
            exit 1
        }
    else
        echo "[!] requirements-ids.txt not found"
        echo "[*] Installing netfilterqueue and scapy..."
        Web-Interface/venv/bin/pip install -q netfilterqueue scapy || {
            echo "[!] Failed to install. Please install system libraries first."
            exit 1
        }
    fi
fi

# Use venv Python with sudo
echo "[*] Starting IDS with database integration..."
echo "[*] Using virtual environment Python"
echo ""

sudo Web-Interface/venv/bin/python3 Web-Interface/run_ids_with_integration.py


