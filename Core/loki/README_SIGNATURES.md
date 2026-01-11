# Signature Engine - YAML vs Database

## Two Signature Engines

### 1. `signature_engine.py` (YAML-based) - This File
- **Purpose**: Standalone YAML-only mode
- **Used when**: Running `nfqueue_app.py` directly
- **Source**: YAML file (`Configs/test_yaml_file.yaml`)
- **Status**: Legacy/standalone mode

### 2. `Web-Interface/integration/db_signature_engine.py` (Database-based)
- **Purpose**: Database-backed signatures (recommended)
- **Used when**: Running `Web-Interface/run_ids_with_integration.py`
- **Source**: SQLite database
- **Status**: Production mode

## Which One is Used?

### When Running with Integration (Recommended)
```bash
sudo python3 Web-Interface/run_ids_with_integration.py
```
- Uses: `db_signature_engine.py` (database)
- This file (`signature_engine.py`) is **NOT used**

### When Running Standalone (Legacy)
```bash
cd Core/loki
sudo python3 nfqueue_app.py
```
- Uses: `signature_engine.py` (YAML)
- No database integration

## Summary

- **This file** = YAML-only mode (standalone)
- **Database engine** = Used by integration script (recommended)
- **Both exist** for different use cases
- **Integration script** = Uses database, not this file


