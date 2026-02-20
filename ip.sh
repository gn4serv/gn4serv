#!/bin/bash

# SAS4 Block External Connection
# Blocks communication with the vendor update server (51.159.23.43)
# -----------------------------

TARGET_IP="51.159.23.43"

# Check if already blocked
if iptables -C OUTPUT -d $TARGET_IP -j DROP 2>/dev/null; then
    echo "Target $TARGET_IP is ALREADY blocked."
    exit 0
fi

# Block outgoing connection
iptables -A OUTPUT -d $TARGET_IP -j DROP

# Verify
if iptables -C OUTPUT -d $TARGET_IP -j DROP 2>/dev/null; then
    echo "SUCCESS: Blocked connection to $TARGET_IP"
    echo "The server can no longer contact the vendor."
else
    echo "ERROR: Failed to add iptables rule. Are you root?"
    exit 1
fi
