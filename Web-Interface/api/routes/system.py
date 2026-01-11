"""
System status and control endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
import psutil
import os
from datetime import datetime

from ..models.database import get_db
from ..models.schemas import SystemStatus, HealthResponse
from ..models import crud

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/status", response_model=SystemStatus)
async def get_system_status(
    db: AsyncSession = Depends(get_db)
):
    """Get IDS system status."""
    # Check if IDS process is running
    ids_running = False
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info.get('cmdline', [])
            if cmdline and any('nfqueue_app.py' in str(arg) or 'run_ids_with_integration.py' in str(arg) for arg in cmdline):
                ids_running = True
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    # Get blacklist size
    blacklist = await crud.get_blacklist(db, active_only=True)
    blacklist_size = len(blacklist)
    
    # Get alerts count for last 24h
    from datetime import timedelta
    yesterday = (datetime.utcnow() - timedelta(days=1)).isoformat()
    alerts, _ = await crud.get_alerts(db, skip=0, limit=1, start_time=yesterday)
    alerts_count_24h = len(alerts) if alerts else 0
    
    return SystemStatus(
        ids_running=ids_running,
        blacklist_size=blacklist_size,
        alerts_count_24h=alerts_count_24h
    )


@router.get("/health", response_model=HealthResponse)
async def health_check(
    db: AsyncSession = Depends(get_db)
):
    """Health check endpoint."""
    try:
        # Test database connection
        from sqlalchemy import text
        await db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return HealthResponse(
        status="healthy" if db_status == "healthy" else "degraded",
        database=db_status,
        timestamp=datetime.utcnow().isoformat()
    )


@router.post("/reload-signatures")
async def reload_ids_signatures():
    """
    Reload IDS signatures from database.
    Works with database-backed signature engine (run_ids_with_db_signatures.py).
    For YAML-based engine, syncs database -> YAML instead.
    """
    try:
        # Try to reload from database (if using database signatures)
        try:
            from integration.db_signature_engine import db_signature_engine
            count = db_signature_engine.reload_rules()
            return {
                "message": f"Reloaded {count} signatures from database",
                "count": count,
                "method": "database",
                "note": "Signatures reloaded in memory - no restart needed!"
            }
        except Exception:
            # Fallback to YAML sync (for YAML-based engine)
            from integration.signature_manager import signature_manager
            count = await signature_manager.sync_db_to_yaml_async()
            return {
                "message": f"Synced {count} signatures to YAML file",
                "count": count,
                "method": "yaml",
                "yaml_file": signature_manager.yaml_file_path,
                "note": "Restart IDS to use updated signatures"
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reloading signatures: {str(e)}")
