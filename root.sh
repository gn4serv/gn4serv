#!/bin/bash

# SAS4 Universal Bypass Installer (Fixed v1.3)
# Created by Antigravity
# -----------------------------

echo "============================================="
echo "   SAS4 LICENSE BYPASS INSTALLER v1.3       "
echo "============================================="

# 1. Check for Manual Inputs
MANUAL_HWID=$1
MANUAL_LICENSE_ID=$2

LICENSE_ID="9629" # Default

if [ ! -z "$MANUAL_LICENSE_ID" ]; then
    LICENSE_ID="$MANUAL_LICENSE_ID"
fi

if [ ! -z "$MANUAL_HWID" ]; then
    echo "[*] Using Manual HWID: $MANUAL_HWID"
    echo "[*] Using License ID: $LICENSE_ID"
    HWID="$MANUAL_HWID"
    # Skip detection logic later if HWID is set
fi

# 2. Stop Existing Services
echo "[*] Stopping original services..."
systemctl stop sas_systemmanager
killall -9 sas_sspd 2>/dev/null
killall -9 python3 2>/dev/null

# 2. Backup Original Binary
if [ ! -f "/opt/sas4/bin/sas_sspd.bak" ]; then
    echo "[*] Backing up original binary..."
    cp /opt/sas4/bin/sas_sspd /opt/sas4/bin/sas_sspd.bak
else
    echo "[*] Backup already exists."
fi

# 4. Capture Real HWID (Only if not provided manually)
if [ -z "$HWID" ]; then
    echo "[*] Starting original binary to capture HWID..."

    # CRITICAL FIX: Change directory first, as sas_sspd relies on relative paths
    cd /opt/sas4/bin
    ./sas_sspd.bak > /dev/null 2>&1 &
    ORIG_PID=$!

    echo "[*] Waiting for server to start (5s)..."
    sleep 5

    echo "[*] Fetching encrypted license..."
    BLOB=$(curl -s "http://127.0.0.1:4000/?op=get")

    if [ -z "$BLOB" ]; then
        echo "[!] Failed to fetch license from original binary."
    else
        echo "[*] Decrypting HWID..."
        # Embedded Python script to brute-force the key and extract HWID
        HWID=$(python3 -c "
import base64
import json

blob = '$BLOB'
try:
    decoded = base64.b64decode(blob)
    
    def xor_crypt(data, key):
        key = key.encode('utf-8')
        res = bytearray()
        k_len = len(key)
        for i in range(len(data)):
            res.append(data[i] ^ key[i % k_len])
        return res

    found = False
    for h in range(24):
        key = f'Gr3nd1z3r{h}'
        try:
            dec = xor_crypt(decoded, key).decode('utf-8')
            if 'hwid' in dec:
                obj = json.loads(dec)
                print(obj['hwid'])
                found = True
                break
        except:
            pass
            
    if not found:
        print('ERROR')
except:
    print('ERROR')
")
    fi

    # Cleanup original process
    kill -9 $ORIG_PID 2>/dev/null
fi

# FALLBACK LOGIC
if [ "$HWID" == "ERROR" ] || [ -z "$HWID" ]; then
    echo "[!] Detection failed. Using Fallback/Known HWID."
    HWID="$KNOWN_HWID"
fi

echo "[+] SUCCESS! Using HWID: $HWID"

# 4. Generate Emulator Script
echo "[*] Generating Emulator..."
cat <<EOF > /opt/sas4/bin/sas_emulator.py
#!/usr/bin/env python3
import http.server
import socketserver
import json
import time
import base64
from datetime import datetime

PORT = 4000
KEY_PREFIX = "Gr3nd1z3r"
TIME_OFFSET = 0 

def get_current_key():
    now_tm = time.localtime()
    current_hour = (now_tm.tm_hour + TIME_OFFSET) % 24
    key_hour = current_hour + 1
    return f"{KEY_PREFIX}{key_hour}"

def xor_crypt(data, key):
    key_bytes = key.encode('utf-8')
    data_bytes = data.encode('utf-8') if isinstance(data, str) else data
    result = bytearray()
    key_len = len(key_bytes)
    for i in range(len(data_bytes)):
        result.append(data_bytes[i] ^ key_bytes[i % key_len])
    return bytes(result)

class LicenseHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self): self.handle_request()
    def do_GET(self): self.handle_request()
    def log_message(self, format, *args): return

    def handle_request(self):
        license_payload = {
            "pid": "100",
            "hwid": "$HWID",
            "exp": "2090-12-31 23:59:59",
            "ftrs": [
                "gp_fup", "gp_daily_limit", "gp_quota_limit",
                "prm_users_index", "prm_users_index_all", "prm_users_index_group",
                "prm_users_create", "prm_users_update", "prm_users_delete",
                "prm_users_rename", "prm_users_cancel", "prm_users_deposit",
                "prm_users_withdrawal", "prm_users_add_traffic", "prm_users_reset_quota",
                "prm_users_pos", "prm_users_advanced", "prm_users_export",
                "prm_users_change_parent", "prm_users_show_password", "prm_users_mac_lock",
                "prm_managers_index", "prm_managers_create", "prm_managers_update",
                "prm_managers_delete", "prm_managers_sysadmin", "prm_sites_management",
                "prm_groups_assign", "prm_tools_bulk_changes"
            ],
            "st": "1",
            "mu": "100000",
            "ms": "100",
            "id": "$LICENSE_ID",
            "hash": "bypassed_by_antigravity"
        }
        
        json_payload = json.dumps(license_payload)
        current_key = get_current_key()
        xor_data = xor_crypt(json_payload, current_key)
        b64_payload = base64.b64encode(xor_data)
        
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-length', str(len(b64_payload)))
        self.end_headers()
        self.wfile.write(b64_payload)

def run_server():
    socketserver.TCPServer.allow_reuse_address = True
    try:
        with socketserver.TCPServer(("", PORT), LicenseHandler) as httpd:
            httpd.serve_forever()
    except OSError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    run_server()
EOF

# 5. Create Systemd Service
echo "[*] Configuring Persistence (Systemd)..."
cat <<EOF > /etc/systemd/system/sas_systemmanager.service
[Unit]
Description=SAS4 System Manager Emulator (Bypassed)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/sas4/bin/sas_emulator.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 6. Enable and Start
echo "[*] Enabling Service..."
systemctl daemon-reload
systemctl enable sas_systemmanager
systemctl start sas_systemmanager

echo "============================================="
echo "   BYPASS INSTALLED SUCCESSFULLY! 🚀        "
echo "   HWID: $HWID                              "
echo "============================================="
