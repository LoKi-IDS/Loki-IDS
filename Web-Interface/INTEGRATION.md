# Integration & Deployment Guide

This guide covers integrating the Web Interface with the core IDS and deploying on Raspberry Pi 5.

**For implementation details, see [IMPLEMENTATION.md](IMPLEMENTATION.md)**

---

## Architecture

### Components

1. **Core IDS** (`Core/loki/`)
   - Packet processing via NFQUEUE
   - Detection engines (port scan, signature matching)
   - Original logger (JSONL file)

2. **Web Interface** (`Web-Interface/`)
   - FastAPI backend API
   - SQLite database
   - Frontend dashboard
   - Integration layer

3. **Integration Layer** (`Web-Interface/integration/`)
   - Database logger (extends core logger)
   - Database blacklist manager
   - IDS integration module

---

## Database Setup

### SQLite Database

**No Docker needed!** SQLite is file-based and requires no separate service.

The database file is automatically created at:
```
/home/zaher/Loki-IDS/Web-Interface/loki_ids.db
```

**Initialization:**
- Database tables are created automatically on first API startup
- No manual setup required

**Backup:**
```bash
# Backup database
cp Web-Interface/loki_ids.db Web-Interface/loki_ids.db.backup

# Restore
cp Web-Interface/loki_ids.db.backup Web-Interface/loki_ids.db
```

---

## Installation

### 1. Install Dependencies

```bash
cd /home/zaher/Loki-IDS/Web-Interface

# Create virtual environment (use clean environment to avoid cursor.AppImage issues)
env -i PATH=/usr/bin:/bin /usr/bin/python3 -m venv venv

# Install Python dependencies
venv/bin/pip install -r requirements.txt
```

### 2. Initialize Database

The database is automatically initialized when you start the API server for the first time.

---

## Running the System

### Option 1: Run IDS with Database Integration (Recommended)

Use the integration wrapper script that enables database signatures, logging, and blacklist:

```bash
cd /home/zaher/Loki-IDS

# Run IDS with integration (requires root for NFQUEUE)
# Must use venv Python to access installed dependencies
sudo ./Web-Interface/start_ids.sh

# Or manually:
sudo Web-Interface/venv/bin/python3 Web-Interface/run_ids_with_integration.py
```

**What this does:**
- Loads signatures directly from database (hot-reloadable, no YAML sync needed)
- Uses database blacklist (persistent across restarts)
- Logs alerts to database (for web dashboard)
- Patches core logger to write to both JSONL and database
- All changes via web interface are immediately available

### Option 2: Run IDS and Web Interface Separately

**Terminal 1 - Start IDS (with integration):**
```bash
cd /home/zaher/Loki-IDS
sudo python3 Web-Interface/run_ids_with_integration.py
```

**Terminal 2 - Start Web Interface:**
```bash
cd /home/zaher/Loki-IDS/Web-Interface
venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8080
```

Or use the startup script:
```bash
./Web-Interface/start_web_server.sh
```

---

## Integration Details

### How Integration Works

1. **Logger Integration** (`integration/db_logger.py`)
   - Extends the core `LokiLogger` class
   - Writes alerts to both JSONL file (original) and SQLite database
   - Uses async database operations for performance
   - Non-blocking (doesn't slow down packet processing)

2. **Blacklist Integration** (`integration/blacklist_manager.py`)
   - Manages blacklist in SQLite database
   - Provides in-memory cache for fast lookups
   - Supports both sync and async operations
   - Compatible with existing code (supports `in` operator and `append()`)

3. **Integration Module** (`integration/ids_integration.py`)
   - Patches core logger at runtime
   - Loads blacklist from database on startup
   - Provides helper functions for IDS integration

### Code Flow

```
Packet → NFQUEUE → process_packet()
                    ↓
            logger.log_alert()  (patched)
                    ↓
        ┌───────────┴───────────┐
        ↓                       ↓
    JSONL File          Database (SQLite)
        ↓                       ↓
    (original)          (web interface)
```

### Blacklist Flow

```
IDS detects threat → blacklist_manager.add_to_blacklist()
                            ↓
                    SQLite Database
                            ↓
                    Web Interface API
                            ↓
                    Dashboard (real-time)
```

---

## Configuration

### API Configuration

The API runs on:
- **Host**: `0.0.0.0` (all interfaces)
- **Port**: `8080`
- **Access**: `http://<raspberry-pi-ip>:8080`

### Database Location

Default: `Web-Interface/loki_ids.db`

To change location, modify `api/models/database.py`:
```python
db_path = os.path.join(project_root, "Web-Interface", "loki_ids.db")
```

### Signature Management

Signatures are stored in the database and loaded directly by the IDS.

**YAML Import (Optional):**
- Use `/api/signatures/reload` to import from YAML file
- Useful for initial setup or bulk import
- YAML file: `Configs/test_yaml_file.yaml`

---

## Systemd Service (Auto-start)

### Create Service File

Create `/etc/systemd/system/loki-web.service`:

```ini
[Unit]
Description=Loki IDS Web Interface
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/zaher/Loki-IDS/Web-Interface
Environment="PATH=/home/zaher/Loki-IDS/Web-Interface/venv/bin"
ExecStart=/home/zaher/Loki-IDS/Web-Interface/venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable loki-web
sudo systemctl start loki-web
sudo systemctl status loki-web
```

### Create IDS Service (with integration)

Create `/etc/systemd/system/loki-ids.service`:

```ini
[Unit]
Description=Loki IDS with Database Integration
After=network.target loki-web.service
Requires=loki-web.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/zaher/Loki-IDS
ExecStart=/usr/bin/python3 /home/zaher/Loki-IDS/Web-Interface/run_ids_with_integration.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Note**: IDS needs root privileges for NFQUEUE.

---

## API Endpoints

### Alerts
- `GET /api/alerts` - List alerts (with pagination, filters)
- `GET /api/alerts/{id}` - Get alert details
- `DELETE /api/alerts/{id}` - Delete alert

### Signatures
- `GET /api/signatures` - List all signatures
- `POST /api/signatures` - Add new signature
- `PUT /api/signatures/{id}` - Update signature
- `DELETE /api/signatures/{id}` - Delete signature
- `POST /api/signatures/reload` - Import from YAML file
- `POST /api/system/reload-signatures` - Hot-reload IDS signatures from database

### Blacklist
- `GET /api/blacklist` - List blacklisted IPs
- `POST /api/blacklist` - Add IP to blacklist
- `DELETE /api/blacklist/{ip}` - Remove IP

### Statistics
- `GET /api/stats` - Get alert statistics

### System
- `GET /api/system/status` - IDS status
- `GET /api/system/health` - Health check
- `POST /api/system/reload-signatures` - Hot-reload IDS signatures from database
- `POST /api/system/reload-signatures` - Hot-reload IDS signatures from database

### WebSocket
- `WS /ws/alerts` - Real-time alert stream

### Documentation
- `GET /docs` - Interactive API documentation (Swagger UI)
- `GET /redoc` - Alternative API documentation

---

## Troubleshooting

### Database Issues

**Problem**: Database locked errors
**Solution**: Ensure only one process accesses the database at a time. SQLite handles concurrent reads well, but writes should be serialized.

**Problem**: Database file not found
**Solution**: Check file permissions. The database is created automatically on first API startup.

### Integration Issues

**Problem**: Alerts not appearing in database
**Solution**: 
1. Check if integration is enabled (look for "Logger patched" message)
2. Check database logger errors in console
3. Verify database file exists and is writable

**Problem**: Blacklist not persisting
**Solution**:
1. Check if blacklist_manager is being used (not the in-memory list)
2. Verify database connection
3. Check for errors in console

### Performance Issues

**Problem**: Slow packet processing
**Solution**:
- Database writes are async and non-blocking
- If still slow, check database file location (should be on fast storage)
- Consider moving database to RAM disk for Raspberry Pi (if you have enough RAM)

**RAM Disk Setup** (optional):
```bash
sudo mkdir -p /mnt/ramdisk
sudo mount -t tmpfs -o size=100M tmpfs /mnt/ramdisk
# Update db_path in database.py to point to /mnt/ramdisk/loki_ids.db
```

### Web Interface Not Accessible

**Problem**: Can't access dashboard
**Solution**:
1. Check if API server is running: `ps aux | grep uvicorn`
2. Check firewall: `sudo ufw allow 8080`
3. Check if port is in use: `netstat -tuln | grep 8080`
4. Check logs for errors

---

## Development vs Production

### Development (Local)

- Use `--reload` flag for auto-reload on code changes
- Access via `http://localhost:8080`
- SQLite database in project directory

### Production (Raspberry Pi)

- Run without `--reload` flag
- Use systemd services for auto-start
- Consider using Nginx as reverse proxy
- Enable HTTPS (optional, for remote access)
- Regular database backups

---

## Backup & Maintenance

### Database Backup

```bash
# Daily backup script
#!/bin/bash
BACKUP_DIR="/home/zaher/backups/loki-ids"
mkdir -p $BACKUP_DIR
cp /home/zaher/Loki-IDS/Web-Interface/loki_ids.db \
   $BACKUP_DIR/loki_ids_$(date +%Y%m%d).db

# Keep only last 7 days
find $BACKUP_DIR -name "loki_ids_*.db" -mtime +7 -delete
```

### Log Rotation

The JSONL log file (`logs/loki_alerts.jsonl`) can grow large. Consider log rotation:

```bash
# Add to crontab
0 0 * * * /home/zaher/Loki-IDS/Scripts/rotate_logs.sh
```

### Database Cleanup

Remove old alerts (optional):
```sql
-- Remove alerts older than 30 days
DELETE FROM alerts WHERE timestamp < datetime('now', '-30 days');
```

---

## Security Considerations

1. **Local Network Only**: By default, the API is accessible on all interfaces. For production:
   - Use firewall rules to restrict access
   - Consider adding authentication
   - Use HTTPS if accessing remotely

2. **Database Permissions**: Ensure database file has proper permissions:
   ```bash
   chmod 600 Web-Interface/loki_ids.db
   ```

3. **API Security**: Consider adding:
   - API key authentication
   - Rate limiting
   - Input validation (already implemented)

---

## Performance Metrics (Raspberry Pi 5)

Expected resource usage:
- **API Server**: ~50-80MB RAM
- **Database**: ~10-20MB (for 10K alerts)
- **Frontend**: Static files (~500KB)
- **Total**: ~100-150MB RAM

The system is designed to be lightweight and efficient for Raspberry Pi 5.

---

## Next Steps

1. **Authentication**: Add user authentication for production
2. **HTTPS**: Set up SSL certificates for secure access
3. **Notifications**: Implement email/webhook notifications
4. **Advanced Analytics**: Add more detailed statistics and visualizations
5. **Mobile App**: Create mobile-friendly interface

---

## Support

For issues or questions:
1. Check logs: `journalctl -u loki-web -f`
2. Check database: `sqlite3 Web-Interface/loki_ids.db "SELECT COUNT(*) FROM alerts;"`
3. Test API: `curl http://localhost:8080/api/system/health`

---

**Last Updated**: 2024

