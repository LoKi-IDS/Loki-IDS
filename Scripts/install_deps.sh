#!/bin/bash
# =================================================================
# Loki IDS - Dependency Installer & Environment Setup
# =================================================================
# This script prepares a Raspberry Pi (Debian/Ubuntu) for Loki IDS.
# It handles:
# 1. System-level C libraries (libnetfilter-queue, libpcap)
# 2. Python Virtual Environment creation (PEP 668 compliant)
# 3. Python package installation (NetfilterQueue, Scapy)
# =================================================================

# Ensure the script stops if any command fails
set -e

# --- Configuration ---
# Get the project root directory (one level up from this script)
PROJECT_ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
VENV_NAME="loki_env"
VENV_PATH="$PROJECT_ROOT/$VENV_NAME"

echo ">>> [LOKI-IDS] Starting Installation..."
echo ">>> [LOKI-IDS] Project Root detected at: $PROJECT_ROOT"

# --- Step 1: System Updates & C Libraries ---
echo ""
echo ">>> [1/3] Installing System Dependencies (Requires Sudo)..."
# Update package list to ensure we get the latest versions
sudo apt update

# Install build tools and headers required to compile the Python bindings
# - build-essential/python3-dev: Needed to compile C extensions
# - libnetfilter-queue-dev: The core C library for NFQUEUE
# - libnfnetlink-dev: Low-level Netlink communication library
# - libpcap-dev: Required by Scapy for packet manipulation
# - python3-venv: Required to create the isolated environment
sudo apt install -y \
    build-essential \
    python3-dev \
    python3-venv \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    libpcap-dev

echo ">>> [1/3] System dependencies installed successfully."

# --- Step 2: Virtual Environment Setup ---
echo ""
echo ">>> [2/3] Setting up Python Virtual Environment..."

if [ -d "$VENV_PATH" ]; then
    echo "    -> Virtual environment '$VENV_NAME' already exists. Skipping creation."
else
    echo "    -> Creating new virtual environment at $VENV_PATH..."
    python3 -m venv "$VENV_PATH"
fi

# --- Step 3: Python Package Installation ---
echo ""
echo ">>> [3/3] Installing Python Libraries into Virtual Environment..."

# We activate the environment temporarily to install packages
source "$VENV_PATH/bin/activate"

# Upgrade pip first to avoid build issues with newer wheels
pip install --upgrade pip

# Install the project requirements
# - NetfilterQueue: The binding to talk to the kernel
# - scapy: For parsing the raw packet bytes
# - pyyaml: For reading your config files
echo "    -> Installing NetfilterQueue, Scapy, and PyYAML..."
pip install NetfilterQueue scapy pyyaml

# Deactivate to return the user's shell to normal state
deactivate

# --- Final Summary ---
echo ""
echo "================================================================="
echo "✅  LOKI IDS INSTALLATION COMPLETE"
echo "================================================================="
echo "To run Loki, use the following commands:"
echo ""
echo "  1. cd $PROJECT_ROOT"
echo "  2. source $VENV_NAME/bin/activate"
echo "  3. sudo python3 ids/loki/nfqueue_app.py"
echo ""
echo "Remember to run 'deactivate' when you are finished."
echo "================================================================="
