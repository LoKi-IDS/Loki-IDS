"""
Integration module that patches the core IDS components to use database.
This should be imported before running the IDS to enable database integration.
"""
import sys
import os

# Add paths
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
core_path = os.path.join(project_root, "Core", "loki")
sys.path.insert(0, core_path)
sys.path.insert(0, os.path.join(project_root, "Web-Interface"))

from integration.db_logger import db_logger
from integration.blacklist_manager import blacklist_manager
# Signature manager kept for YAML sync if needed (optional)
try:
    from integration.signature_manager import signature_manager
except ImportError:
    signature_manager = None


def patch_logger():
    """
    Patch the core logger to also write to database.
    This extends the existing logger without breaking it.
    """
    try:
        from logger import logger as core_logger
        
        # Store original log_alert method
        original_log_alert = core_logger.log_alert
        
        def enhanced_log_alert(alert_type, src_ip, dst_ip, src_port, dst_port, message, details=None):
            # Call original logger (console + JSONL file)
            original_log_alert(alert_type, src_ip, dst_ip, src_port, dst_port, message, details)
            
            # Also log to database
            db_logger.log_alert(alert_type, src_ip, dst_ip, src_port, dst_port, message, details)
        
        # Replace method
        core_logger.log_alert = enhanced_log_alert
        print("[*] Logger patched for database integration")
        return True
    except Exception as e:
        print(f"[!] Error patching logger: {e}")
        return False


def get_blacklist_from_db():
    """
    Get blacklist from database.
    This should be called at IDS startup.
    """
    try:
        blacklist = blacklist_manager.load_blacklist()
        print(f"[*] Loaded {len(blacklist)} IPs from database blacklist")
        return blacklist
    except Exception as e:
        print(f"[!] Error loading blacklist from database: {e}")
        return []


def add_to_blacklist_db(ip_address: str, reason: str = None):
    """
    Add IP to blacklist in database.
    This can be called from the IDS when detecting threats.
    """
    return blacklist_manager.add_to_blacklist(ip_address, reason)


def sync_signatures_to_yaml():
    """
    Sync signatures from database to YAML file (optional, for backup).
    Note: With database-backed signatures, this is not needed.
    """
    if signature_manager is None:
        return 0
    try:
        count = signature_manager.sync_db_to_yaml()
        print(f"[*] Synced {count} signatures from database to YAML")
        return count
    except Exception as e:
        print(f"[!] Error syncing signatures: {e}")
        return 0


def enable_integration():
    """
    Enable full database integration.
    Call this before starting the IDS.
    """
    print("[*] Enabling database integration...")
    patch_logger()
    blacklist = get_blacklist_from_db()
    # Note: Signatures are now loaded directly from database, no YAML sync needed
    print("[*] Database integration enabled")
    return blacklist

