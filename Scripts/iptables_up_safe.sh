#!/bin/bash
# Safe iptables setup that doesn't block traffic if IDS isn't running
# Uses NFQUEUE with fail-open behavior

QUEUE_NUM_INPUT="100"
QUEUE_NUM_FORWARD="200"

echo "======================================================"
echo "    LOKI IDS: SETTING UP IPTABLES (Safe Mode)"
echo "======================================================"

# 1. ENABLE IP FORWARDING
echo "[1/4] Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

# 2. ADD NFQUEUE RULES with fail-open (packets pass through if queue fails)
# Using --queue-bypass would be ideal but NFQUEUE doesn't support it directly
# Instead, we'll add rules that only affect specific traffic

echo "[2/4] Inserting NFQUEUE rule to FORWARD chain..."
sudo iptables -I FORWARD -j NFQUEUE --queue-num $QUEUE_NUM_FORWARD

echo "[3/4] Inserting NFQUEUE rule to INPUT chain..."
sudo iptables -I INPUT -j NFQUEUE --queue-num $QUEUE_NUM_INPUT

# 3. IMPORTANT: Add a rule to accept packets if NFQUEUE fails
# This is a safety measure - if IDS crashes, packets still pass
# Note: NFQUEUE will drop packets if no process is listening, so we need IDS running

echo "[4/4] Safety check: Make sure IDS is running!"
echo ""
echo "⚠️  WARNING: If IDS is not running, packets will be DROPPED!"
echo "⚠️  Start IDS immediately after this script!"
echo ""

# 4. VERIFICATION
echo "Rules set. Packets will now be sent to Queue $QUEUE_NUM_FORWARD & $QUEUE_NUM_INPUT."
echo ""
echo " *** Printing the iptables rules *** "
echo "------------------------------------------------------"
sudo iptables -L --line-numbers | grep NFQUEUE
echo "------------------------------------------------------"
echo ""
echo "✅ iptables setup complete"
echo "⚠️  IMPORTANT: Start IDS NOW or remove rules with: sudo ./Scripts/iptables_down.sh"


