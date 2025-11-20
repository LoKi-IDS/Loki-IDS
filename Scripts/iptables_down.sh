#!/bin/bash

QUEUE_NUM_INPUT="100"
QUEUE_NUM_FORWARD="200"

echo "======================================================"
echo "    LOKI IDS: SAFELY FLUSHING NFQUEUE RULES"
echo "======================================================"

# 1. IDENTIFY AND DELETE NFQUEUE RULES
# Delete the NFQUEUE rule from the FORWARD chain
echo "[+] Deleting NFQUEUE rule from FORWARD chain..."
sudo iptables -D FORWARD -j NFQUEUE --queue-num $QUEUE_NUM_FORWARD 2>/dev/null 

# Delete the NFQUEUE rule from the INPUT chain
echo "[+] Deleting NFQUEUE rule from INPUT chain..."
sudo iptables -D INPUT -j NFQUEUE --queue-num $QUEUE_NUM_INPUT 2>/dev/null

# 2. VERIFICATION
echo "[+] Remaining NFQUEUE rules (should be empty):"
sudo iptables -L --line-numbers | grep NFQUEUE
echo "------------------------------------------------------"
echo "[+] IPTABLES cleanup complete."
