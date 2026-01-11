# Complete Local Testing Guide

## ⚠️ IMPORTANT: Internet Connection

**If you lose internet after running iptables:**
1. **Start IDS immediately** - Packets are queued and need IDS to process them
2. **Or remove iptables rules**: `sudo ./Scripts/iptables_down.sh`

**The IDS must be running when iptables rules are active**, otherwise packets get stuck in the queue.

---

## Prerequisites

1. **Python 3.12+** installed
2. **Root/sudo access** (for IDS - NFQUEUE requires root)
3. **Network access** (for testing packet interception)
4. **iptables** installed (for packet interception)

---

## Complete Testing with IDS

This guide covers testing the full system: Web Interface + IDS + Database Integration.

### Quick Start (All Steps)

```bash
# Terminal 1: Start Web Interface
cd /home/zaher/Loki-IDS/Web-Interface
venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8080 --reload

# Terminal 2: Setup iptables & Start IDS (Recommended: use combined script)
cd /home/zaher/Loki-IDS
sudo ./Scripts/start_ids_with_iptables.sh  # Does both together - prevents internet loss

# Terminal 3: Add signature & test
# 1. Add signature via dashboard: http://localhost:8080
# 2. Generate test traffic (see Step 8)
# 3. Check alerts in dashboard
```

**⚠️ CRITICAL:** Start IDS immediately after iptables, or you'll lose internet!

---

## Step 1: Setup Environment

```bash
cd /home/zaher/Loki-IDS/Web-Interface

# Create virtual environment (if not exists)
if [ ! -d "venv" ]; then
    env -i PATH=/usr/bin:/bin /usr/bin/python3 -m venv venv
fi

# Install dependencies
venv/bin/pip install -r requirements.txt
```

---

## Step 2: Start Web Interface

**Terminal 1:**
```bash
cd /home/zaher/Loki-IDS/Web-Interface
venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8080 --reload
```

**Expected output:**
```
INFO:     Started server process
[*] Database initialized
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8080
```

**Verify it's working:**
```bash
# In another terminal
curl http://localhost:8080/api/system/health
```

Should return:
```json
{"status":"healthy","database":"healthy","timestamp":"..."}
```

---

## Step 3: Access Dashboard

Open browser: **http://localhost:8080**

You should see:
- Dashboard with statistics
- Empty alerts list (initially)
- Empty signatures list (initially)
- Empty blacklist (initially)

---

## Step 4: Add Test Signatures

### Via Dashboard (Recommended)

1. Go to **Signatures** tab
2. Click **"+ Add Signature"**
3. Fill in:
   - Name: `Test Signature`
   - Pattern: `TEST_PATTERN`
   - Action: `alert`
   - Description: `Test signature for local testing`
4. Click **"Add Signature"**

### Via API

```bash
curl -X POST http://localhost:8080/api/signatures \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SQL Injection Test",
    "pattern": "UNION SELECT",
    "action": "alert",
    "description": "Test SQL injection detection"
  }'
```

**Verify:**
- Refresh dashboard → Signatures tab
- You should see the new signature

---

## Step 5: Import Existing YAML Signatures (Optional)

If you have signatures in `Configs/test_yaml_file.yaml`:

1. Go to **Signatures** tab
2. Click **"Import from YAML"**
3. Signatures from YAML will be imported to database

Or via API:
```bash
curl -X POST http://localhost:8080/api/signatures/reload
```

---

## Step 6: Setup iptables (Required for Packet Interception)

**⚠️ CRITICAL: Start IDS immediately after this step!**

**Terminal 2 (requires sudo):**
```bash
cd /home/zaher/Loki-IDS

# Setup iptables rules for NFQUEUE
sudo ./Scripts/iptables_up.sh
```

**Expected output:**
```
======================================================
    LOKI IDS: SETTING UP IPTABLES FOR ROUTING
======================================================
[1/3] Enabling IP forwarding...
[2/3] Inserting NFQUEUE rule to FORWARD chain...
[2/3] Inserting NFQUEUE rule to INPUT chain...
[3/3] Rules set. Packets will now be sent to Queue 200 & 100.
```

**⚠️ WARNING:** 
- **Internet will stop working** if IDS is not running!
- **Start IDS immediately** in the next step!

**Verify iptables rules:**
```bash
sudo iptables -L -n | grep NFQUEUE
```

Should show:
```
NFQUEUE  tcp  --  0.0.0.0/0  0.0.0.0/0  NFQUEUE num 100
NFQUEUE  tcp  --  0.0.0.0/0  0.0.0.0/0  NFQUEUE num 200
```

---

## Step 7: Start IDS with Database Integration

**⚠️ START THIS IMMEDIATELY AFTER STEP 6!**

**Terminal 2 (keep running, requires sudo):**
```bash
cd /home/zaher/Loki-IDS

# Use startup script (uses venv Python)
sudo ./Web-Interface/start_ids.sh

# Or manually:
sudo Web-Interface/venv/bin/python3 Web-Interface/run_ids_with_integration.py
```

**Expected output:**
```
[*] Enabling database integration...
[*] Logger patched for database integration
[*] Loaded X IPs from database blacklist
[*] Loading signatures from database...
[*] Loaded X signatures from database
========== Starting LOKI IDS (Database Integration) ==========
 ### The Threads have started ###
 ### Loaded X IPs from database blacklist ###
 ### Loaded X signatures from database ###
```

**Important:** 
- The IDS should show the number of signatures you added via web interface!
- If it shows "0 signatures", add signatures via dashboard first (Step 4)
- **Once IDS is running, internet should work again!**

---

## Step 8: Test Signature Detection

### Generate Test Traffic

**Terminal 3 (new terminal):**

**Method 1: Using curl (Recommended)**
```bash
# Send HTTP request with test pattern in payload
curl -X POST http://localhost:8080 -d "TEST_PATTERN" 2>/dev/null || true
```

**Method 2: Using netcat**
```bash
# Send raw data with test pattern
echo "TEST_PATTERN" | nc localhost 80 2>/dev/null || echo "Test packet sent"
```

**Method 3: Using telnet**
```bash
# Connect and send test pattern
echo -e "GET / HTTP/1.1\nHost: localhost\n\nTEST_PATTERN" | telnet localhost 80 2>/dev/null || true
```

**Note:** The IDS will intercept these packets and check for signature matches.

### Check for Alerts

**Option 1: Dashboard (Recommended)**
1. Go to **Alerts** tab in browser
2. You should see a new alert with type "SIGNATURE"
3. Alert should show: "Signature Match: Test Signature"
4. Alert details should include source IP, destination IP, ports, etc.

**Option 2: API**
```bash
# Get latest alerts
curl http://localhost:8080/api/alerts?page=1&page_size=10 | python3 -m json.tool

# Check alert count
curl http://localhost:8080/api/stats | python3 -m json.tool
```

**Option 3: Check IDS Terminal**
- Look at Terminal 2 (IDS output)
- Should show: `[SIGNATURE] ... Signature Match: Test Signature`
- Should also show packet processing logs

**Option 4: Check Database Directly**
```bash
sqlite3 Web-Interface/loki_ids.db "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5;"
```

---

## Step 9: Test Blacklist

### Add IP to Blacklist

**Via Dashboard:**
1. Go to **Blacklist** tab
2. Enter IP: `192.168.1.100`
3. Reason: `Test entry`
4. Click **"Add IP"**

**Via API:**
```bash
curl -X POST http://localhost:8080/api/blacklist \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.100", "reason": "Test"}'
```

**Verify:**
- Dashboard → Blacklist tab shows the IP
- API: `curl http://localhost:8080/api/blacklist`

---

## Step 10: Test Hot-Reload Signatures

This is a key feature - reload signatures without restarting IDS!

### Add New Signature While IDS is Running

1. **Add signature via dashboard:**
   - Go to **Signatures** tab
   - Click **"+ Add Signature"**
   - Name: `Hot Reload Test`
   - Pattern: `HOT_RELOAD_TEST`
   - Action: `alert`
   - Click **"Add Signature"**

2. **Reload IDS signatures:**
   - Click **"Reload IDS Signatures"** button
   - Or use API: `curl -X POST http://localhost:8080/api/system/reload-signatures`

3. **Verify reload:**
   - Check Terminal 2 (IDS) - should show reload message
   - Should show: `[*] Reloaded X signatures from database`

4. **Test the new signature:**
   ```bash
   # Send test traffic with new pattern
   curl -X POST http://localhost:8080 -d "HOT_RELOAD_TEST" 2>/dev/null || true
   ```

5. **Check for alert:**
   - Dashboard → Alerts tab
   - Should see alert for "Hot Reload Test" signature
   - **No IDS restart needed!** ✅

---

## Step 11: Test Port Scan Detection

The IDS also detects port scans (behavioral detection).

**Generate port scan (Terminal 3):**
```bash
# Option 1: Use nmap (if installed)
nmap -p 1-100 localhost

# Option 2: Use hping3 (if installed)
sudo hping3 -S -p ++1 localhost

# Option 3: Use Python script
python3 -c "
import socket
for port in range(80, 90):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect(('localhost', port))
        s.close()
    except:
        pass
"
```

**Check alerts:**
- Dashboard → Alerts tab
- Should show "Port Scan Detected" alerts
- Type: "BEHAVIOR" or "BLACKLIST"

---

## Step 12: Verify Real-Time Updates

1. **Keep dashboard open** on **Alerts** tab
2. **Generate test traffic** (Step 8)
3. **Dashboard should update automatically** (via WebSocket)
4. **If WebSocket doesn't work**, refresh page to see new alerts

---

## Step 13: Test Statistics

**Dashboard:**
- Go to **Dashboard** tab
- Should show:
  - Total alerts count
  - Alerts by type (pie chart)
  - Top attacking IPs
  - Recent alerts

**API:**
```bash
curl http://localhost:8080/api/stats | python3 -m json.tool
```

**Verify:**
- Statistics should match actual alerts
- Charts should update with new data

---

## Step 14: Cleanup

**Stop IDS:**
- Press `Ctrl+C` in Terminal 2 (IDS)

**⚠️ IMPORTANT: Remove iptables rules to restore internet:**
```bash
cd /home/zaher/Loki-IDS
sudo ./Scripts/iptables_down.sh
```

**Stop web interface:**
- Press `Ctrl+C` in Terminal 1 (Web Interface)

**Verify cleanup:**
```bash
# Check iptables (should be empty of NFQUEUE rules)
sudo iptables -L -n | grep NFQUEUE

# Should return nothing (or only if other services use NFQUEUE)
```

---

## Troubleshooting

### Lost Internet Connection?

**Problem:** Internet stops working after running iptables

**Solution:**
1. **Start IDS immediately** - Packets are queued and need IDS to process them
   ```bash
   sudo ./Web-Interface/start_ids.sh
   ```

2. **Or remove iptables rules:**
   ```bash
   sudo ./Scripts/iptables_down.sh
   ```

**Why this happens:**
- NFQUEUE intercepts ALL packets
- If IDS isn't running, packets get stuck in queue
- IDS must be running to process queued packets

**Prevention:**
- Always start IDS immediately after iptables
- Or use a script that does both together

### IDS doesn't detect signatures
- Check IDS terminal - should show "Loaded X signatures from database"
- Verify signature is enabled in database
- Check pattern matches test traffic

### No alerts in dashboard
- Check IDS is running
- Verify iptables rules are set
- Check database: `sqlite3 Web-Interface/loki_ids.db "SELECT * FROM alerts;"`

### Database errors
- Check database file exists: `ls -lh Web-Interface/loki_ids.db`
- Check permissions: `chmod 644 Web-Interface/loki_ids.db`

### Port already in use
```bash
# Find process using port 8080
sudo lsof -i :8080
# Use different port
uvicorn api.main:app --host 0.0.0.0 --port 8081
```

---

## Complete Test Checklist

### Setup
- [ ] Web interface starts successfully
- [ ] Dashboard loads at http://localhost:8080
- [ ] iptables rules are set up
- [ ] IDS starts and loads signatures from database
- [ ] Internet connection works (IDS is processing packets)

### Signature Testing
- [ ] Can add signature via dashboard
- [ ] IDS shows correct signature count on startup
- [ ] IDS detects test pattern and creates alert
- [ ] Alert appears in dashboard (real-time or after refresh)
- [ ] Alert details are correct (IP, ports, pattern, etc.)
- [ ] Hot-reload signatures works (no restart needed)

### Blacklist Testing
- [ ] Can add IP to blacklist via dashboard
- [ ] Blacklist persists (survives IDS restart)
- [ ] IDS loads blacklist from database

### Statistics & Analytics
- [ ] Statistics show on dashboard
- [ ] Charts display correctly
- [ ] Top attacking IPs list updates
- [ ] Alert counts are accurate

### API Testing
- [ ] All API endpoints respond correctly
- [ ] Health check returns healthy
- [ ] System status shows IDS running
- [ ] WebSocket connection works (real-time updates)

### Integration Testing
- [ ] Signatures added via web UI are used by IDS
- [ ] Alerts from IDS appear in dashboard
- [ ] Blacklist changes affect IDS behavior
- [ ] Database persists all data correctly

---

## Expected Test Results

After completing all steps:

1. **Dashboard** shows:
   - Statistics with alert counts
   - List of signatures
   - List of blacklisted IPs
   - Recent alerts

2. **IDS** shows:
   - Signatures loaded from database
   - Alerts logged to console
   - Packets being processed
   - Internet connection working

3. **Database** contains:
   - Signatures table with your test signatures
   - Alerts table with detection events
   - Blacklist table with blocked IPs

---

## Next Steps

Once local testing is successful:
1. Deploy to Raspberry Pi 5
2. Set up systemd services (see INTEGRATION.md)
3. Configure firewall rules
4. Set up backups

---

**Happy Testing! 🛡️**
