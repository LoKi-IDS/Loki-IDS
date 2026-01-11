# Loki IDS Web Interface

A lightweight web dashboard for managing and monitoring the Loki Intrusion Detection System, optimized for Raspberry Pi 5.

## Features

- 📊 **Real-time Dashboard**: Live monitoring of IDS status and alerts
- 🚨 **Alert Management**: View, filter, and manage security alerts
- 🔍 **Signature Management**: Add, edit, and manage detection signatures via web UI
- 🚫 **Blacklist Management**: Manage blocked IP addresses
- 📈 **Analytics**: Statistics and visualizations of security events
- 🔌 **WebSocket Support**: Real-time alert streaming
- 💾 **Database-Backed**: SQLite database for persistent storage

## Quick Start

### 1. Setup Environment

```bash
cd /home/zaher/Loki-IDS/Web-Interface

# Create virtual environment
env -i PATH=/usr/bin:/bin /usr/bin/python3 -m venv venv

# Install dependencies
venv/bin/pip install -r requirements.txt
```

### 2. Start the Web Interface

```bash
# Start server
venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8080 --reload
```

Or use the startup script:
```bash
./start_web_server.sh
```

### 3. Access the Dashboard

Open your browser:
- **Dashboard**: http://localhost:8080
- **API Docs**: http://localhost:8080/docs

## Running IDS with Integration

**Terminal 1 - Start Web Interface:**
```bash
cd /home/zaher/Loki-IDS/Web-Interface
venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8080
```

**Terminal 2 - Setup iptables & Start IDS:**
```bash
cd /home/zaher/Loki-IDS

# Option 1: Combined script (recommended - prevents internet loss)
sudo ./Scripts/start_ids_with_iptables.sh

# Option 2: Separate steps (must start IDS immediately after iptables!)
sudo ./Scripts/iptables_up.sh
sudo ./Web-Interface/start_ids.sh  # START IMMEDIATELY!

# Option 3: Manual start (must use venv Python)
sudo ./Scripts/iptables_up.sh
sudo Web-Interface/venv/bin/python3 Web-Interface/run_ids_with_integration.py
```

**⚠️ CRITICAL:** If you run iptables separately, **start IDS immediately** or you'll lose internet connection!

**Note**: IDS requires root privileges for NFQUEUE.

**What this enables:**
- **Database signatures** - Loads directly from database (hot-reloadable)
- **Database logging** - Alerts saved to SQLite
- **Persistent blacklist** - Survives restarts
- **Real-time dashboard** - Live updates via WebSocket

## Architecture

### Database-First Design
- **Signatures**: Loaded from database into memory (fast packet processing)
- **Blacklist**: Managed in database (persistent)
- **Alerts**: Logged to database (queryable, searchable)

### Components
- **FastAPI Backend**: RESTful API with WebSocket support
- **SQLite Database**: File-based, zero-configuration
- **Frontend Dashboard**: Vanilla JavaScript (lightweight)
- **Integration Layer**: Seamlessly connects IDS with web interface

## API Endpoints

### Alerts
- `GET /api/alerts` - List alerts (pagination, filters)
- `GET /api/alerts/{id}` - Get alert details
- `DELETE /api/alerts/{id}` - Delete alert

### Signatures
- `GET /api/signatures` - List all signatures
- `POST /api/signatures` - Add new signature
- `PUT /api/signatures/{id}` - Update signature
- `DELETE /api/signatures/{id}` - Delete signature
- `POST /api/signatures/reload` - Import from YAML file

### Blacklist
- `GET /api/blacklist` - List blacklisted IPs
- `POST /api/blacklist` - Add IP to blacklist
- `DELETE /api/blacklist/{ip}` - Remove from blacklist

### System
- `GET /api/stats` - Get statistics
- `GET /api/system/status` - IDS status
- `GET /api/system/health` - Health check
- `POST /api/system/reload-signatures` - Hot-reload IDS signatures

### WebSocket
- `WS /ws/alerts` - Real-time alert stream

Full API documentation: http://localhost:8080/docs

## Database

**SQLite** (file-based, no separate server):
- **Location**: `Web-Interface/loki_ids.db`
- **Auto-created** on first startup
- **No configuration** required
- **No Docker** needed

## Testing

See [TESTING_GUIDE.md](TESTING_GUIDE.md) for complete step-by-step testing instructions.

**Quick test:**
```bash
# Health check
curl http://localhost:8080/api/system/health

# Get statistics
curl http://localhost:8080/api/stats
```

## Project Structure

```
Web-Interface/
├── api/                    # FastAPI backend
│   ├── main.py            # Main application
│   ├── models/            # Database models and schemas
│   └── routes/            # API endpoints
├── integration/           # Core IDS integration
│   ├── db_logger.py      # Database logger
│   ├── db_signature_engine.py  # Database signature engine
│   ├── blacklist_manager.py
│   └── ids_integration.py
├── static/                # Frontend files
│   ├── index.html
│   ├── css/
│   └── js/
├── requirements.txt
├── run_ids_with_integration.py  # IDS integration wrapper
└── start_web_server.sh
```

## Troubleshooting

### Port Already in Use
```bash
sudo lsof -i :8080
# Use different port: uvicorn api.main:app --host 0.0.0.0 --port 8081
```

### Import Errors
```bash
venv/bin/pip install -r requirements.txt
```

### Database Errors
```bash
# Remove and recreate (will lose data)
rm Web-Interface/loki_ids.db
# Restart server (will auto-create)
```

## Deployment

See [INTEGRATION.md](INTEGRATION.md) for:
- Systemd service setup
- Production deployment
- Backup procedures

## License

See main project LICENSE file.
