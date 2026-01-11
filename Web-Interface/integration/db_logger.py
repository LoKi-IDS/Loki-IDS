"""
Database-integrated logger that extends the core LokiLogger.
This module provides a logger that writes alerts to both the JSONL file
and the SQLite database for the web interface.
"""
import json
import asyncio
from datetime import datetime
import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(project_root, "Web-Interface"))

from api.models.database import AsyncSessionLocal
from api.models import crud


class DatabaseLogger:
    """
    Logger that writes alerts to the database.
    This should be used alongside the core LokiLogger.
    """
    def __init__(self):
        self.enabled = True
    
    async def log_alert_async(
        self,
        alert_type: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        message: str,
        details: dict = None
    ):
        """Async method to log alert to database."""
        if not self.enabled:
            return
        
        try:
            async with AsyncSessionLocal() as session:
                alert_data = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "type": alert_type,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "message": message,
                    "details": json.dumps(details) if details else None,
                    "severity": self._determine_severity(alert_type)
                }
                await crud.create_alert(session, alert_data)
        except Exception as e:
            print(f"[!] Database logger error: {e}")
    
    def log_alert(
        self,
        alert_type: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        message: str,
        details: dict = None
    ):
        """Synchronous wrapper for async logging."""
        try:
            # Try to get or create event loop
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            # Schedule the async task
            if loop.is_running():
                # If loop is already running, schedule as task
                asyncio.create_task(
                    self.log_alert_async(
                        alert_type, src_ip, dst_ip, src_port, dst_port, message, details
                    )
                )
            else:
                # If loop is not running, run it
                loop.run_until_complete(
                    self.log_alert_async(
                        alert_type, src_ip, dst_ip, src_port, dst_port, message, details
                    )
                )
        except Exception as e:
            print(f"[!] Error in database logger: {e}")
    
    def _determine_severity(self, alert_type: str) -> str:
        """Determine alert severity based on type."""
        severity_map = {
            "SIGNATURE": "HIGH",
            "BEHAVIOR": "MEDIUM",
            "BLACKLIST": "MEDIUM"
        }
        return severity_map.get(alert_type, "MEDIUM")


# Global instance
db_logger = DatabaseLogger()


