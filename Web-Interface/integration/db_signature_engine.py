"""
Database-backed signature engine for IDS.
Loads signatures from database into memory for fast packet processing.
"""
import sys
import os
import asyncio
from typing import List, Dict, Any

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(project_root, "Web-Interface"))

from api.models.database import AsyncSessionLocal
from api.models import crud


class DatabaseSignatureEngine:
    """
    Signature engine that loads signatures from database into memory.
    Provides fast in-memory lookups for packet processing.
    """
    def __init__(self):
        self.rules: List[Dict[str, Any]] = []
        self._rules_loaded = False
    
    async def load_rules_async(self):
        """Load enabled signatures from database into memory."""
        try:
            async with AsyncSessionLocal() as session:
                signatures = await crud.get_signatures(session, enabled_only=True)
                
                self.rules = []
                for sig in signatures:
                    rule = {
                        'name': sig.name,
                        'pattern': sig.pattern,
                        'pattern_bytes': sig.pattern.encode('utf-8'),
                        'action': sig.action,
                        'description': sig.description or ''
                    }
                    self.rules.append(rule)
                
                self._rules_loaded = True
                print(f"[*] Loaded {len(self.rules)} signatures from database")
                return len(self.rules)
        except Exception as e:
            print(f"[!] Error loading signatures from database: {e}")
            # Keep existing rules if available
            if not self._rules_loaded:
                self.rules = []
            raise
    
    def load_rules(self):
        """Synchronous wrapper to load rules from database."""
        # For initial load, we need to ensure we can run async code
        try:
            # Try to get existing event loop
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                # No event loop exists, create one
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            if loop.is_running():
                # If loop is already running, use nest_asyncio
                try:
                    import nest_asyncio
                    nest_asyncio.apply()
                    return loop.run_until_complete(self.load_rules_async())
                except ImportError:
                    # nest_asyncio not available, try to create new loop
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        return loop.run_until_complete(self.load_rules_async())
                    finally:
                        loop.close()
            else:
                # Loop exists but not running
                return loop.run_until_complete(self.load_rules_async())
        except Exception as e:
            print(f"[!] Error in load_rules: {e}")
            # Fallback: return empty rules
            self.rules = []
            self._rules_loaded = False
            return 0
    
    def reload_rules(self):
        """Reload rules from database (for hot-reload)."""
        print("[*] Reloading signatures from database...")
        count = self.load_rules()
        print(f"[*] Reloaded {count} signatures")
        return count
    
    def check_packet_payload(self, payload: bytes):
        """
        Check packet payload against signatures.
        Returns: (rule_name, pattern, action) or (None, None, None)
        """
        if not self._rules_loaded or not self.rules:
            return None, None, None
        
        try:
            for rule in self.rules:
                if rule.get('pattern_bytes') in payload:
                    action = rule.get('action', 'alert')
                    # Convert 'drop' to boolean for compatibility
                    drop = (action.lower() == 'drop')
                    return rule.get('name'), rule.get('pattern'), drop
        except Exception as e:
            print(f"[-] ERROR while checking packet payload: {e}")
        
        return None, None, None


# Global instance
db_signature_engine = DatabaseSignatureEngine()

