#!/bin/bash
QUEUE_NUM_INPUT="100" # for the input chain
QUEUE_NUM_FORWARD="200" # for the forward chain

echo "======================================================"
echo "    LOKI IDS: SETTING UP IPTABLES FOR ROUTING"
echo "======================================================"

# 1. ENABLE IP FORWARDING 
echo "[1/3] Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

# 2. ADD NFQUEUE RULES (Insert at the top of the chain: -I)
# We target the FORWARD chain for traffic passing through the Pi.
echo "[2/3] Inserting NFQUEUE rule to FORWARD chain..."
sudo iptables -I FORWARD -j NFQUEUE --queue-num $QUEUE_NUM_FORWARD

# We also insert the rule into the INPUT chain to inspect traffic aimed at the Pi itself.
echo "[2/3] Inserting NFQUEUE rule to INPUT chain (for traffic to the Pi itself)..."
sudo iptables -I INPUT -j NFQUEUE --queue-num $QUEUE_NUM_INPUT

# 3. VERIFICATION
echo "[3/3] Rules set. Packets will now be sent to Queue $QUEUE_NUM_FORWARD & $QUEUE_NUM_INPUT."

echo " *** Printing the iptables rules *** "

echo "------------------------------------------------------"
sudo iptables -L --line-numbers | grep NFQUEUE
echo "------------------------------------------------------"
