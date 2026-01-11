#!/usr/bin/env python3
"""
Run Loki IDS with database-backed signatures (recommended approach).
Signatures are loaded from database into memory for fast packet processing.
"""
import sys
import os

# Add paths
project_root = os.path.dirname(os.path.dirname(__file__))
core_path = os.path.join(project_root, "Core", "loki")
sys.path.insert(0, core_path)
sys.path.insert(0, os.path.join(project_root, "Web-Interface"))

# Enable integration before importing IDS modules
from integration.ids_integration import enable_integration
from integration.db_signature_engine import db_signature_engine

# Enable database integration
blacklist = enable_integration()

# Load signatures from database
print("[*] Loading signatures from database...")
db_signature_engine.load_rules()

# Create a wrapper class that matches the original SignatureScanning interface
class SignatureScannerWrapper:
    """Wrapper to make database signature engine compatible with existing code."""
    def __init__(self, db_engine):
        self.db_engine = db_engine
        self.rules = db_engine.rules  # Expose rules for compatibility
    
    def CheckPacketPayload(self, payload):
        """Compatible method name for existing code."""
        return self.db_engine.check_packet_payload(payload)
    
    def reload_rules(self):
        """Reload rules from database."""
        return self.db_engine.reload_rules()

# Create signature scanner
sig_object = SignatureScannerWrapper(db_signature_engine)

# Now import and run the IDS
from nfqueue_app import input_agent, forward_agent
from logger import logger
import threading
import time

if __name__ == "__main__":
    logger.console_logger.info("========== Starting LOKI IDS (Database Signatures) ==========")
    
    if sig_object:
        # Use database blacklist
        from integration.blacklist_manager import blacklist_manager
        
        # Start IDS threads
        input_thread = threading.Thread(
            target=input_agent,
            args=(sig_object, blacklist_manager,),
            daemon=True
        )
        forward_thread = threading.Thread(
            target=forward_agent,
            args=(sig_object, blacklist_manager,),
            daemon=True
        )
        
        input_thread.start()
        forward_thread.start()
        
        logger.console_logger.info(" ### The Threads have started ### ")
        logger.console_logger.info(f" ### Loaded {len(blacklist_manager.get_blacklist())} IPs from database blacklist ### ")
        logger.console_logger.info(f" ### Loaded {len(sig_object.rules)} signatures from database ### ")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        logger.console_logger.info("[*] Received ^C, Quitting...")
        logger.console_logger.info(" ========== Stopping LOKI IDS ==========")


