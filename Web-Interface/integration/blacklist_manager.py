"""
Blacklist manager that syncs with the database.
This provides a shared blacklist that persists across IDS restarts.
"""
import asyncio
import sys
import os
from typing import List, Set

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(project_root, "Web-Interface"))

from api.models.database import AsyncSessionLocal
from api.models import crud


class DatabaseBlacklistManager:
    """
    Manages blacklist by syncing with database.
    Provides both async and sync interfaces.
    Can be used like a list for compatibility with existing code.
    """
    def __init__(self):
        self._cache: Set[str] = set()
        self._cache_loaded = False
        self._list_cache: List[str] = []
    
    async def load_blacklist_async(self) -> List[str]:
        """Load blacklist from database."""
        try:
            async with AsyncSessionLocal() as session:
                entries = await crud.get_blacklist(session, active_only=True)
                ip_list = [entry.ip_address for entry in entries]
                self._cache = set(ip_list)
                self._list_cache = ip_list
                self._cache_loaded = True
                return ip_list
        except Exception as e:
            print(f"[!] Error loading blacklist: {e}")
            return []
    
    def load_blacklist(self) -> List[str]:
        """Synchronous wrapper to load blacklist."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        if loop.is_running():
            # If loop is running, we can't use run_until_complete
            # So we'll just use the cache if available
            if not self._cache_loaded:
                # Schedule async load
                asyncio.create_task(self.load_blacklist_async())
            return list(self._cache)
        else:
            return loop.run_until_complete(self.load_blacklist_async())
    
    def is_blacklisted(self, ip_address: str) -> bool:
        """Check if IP is blacklisted (uses cache)."""
        if not self._cache_loaded:
            self.load_blacklist()
        return ip_address in self._cache
    
    async def add_to_blacklist_async(self, ip_address: str, reason: str = None) -> bool:
        """Add IP to blacklist in database."""
        try:
            async with AsyncSessionLocal() as session:
                await crud.add_to_blacklist(session, ip_address, reason, added_by="system")
                self._cache.add(ip_address)
                return True
        except Exception as e:
            print(f"[!] Error adding to blacklist: {e}")
            return False
    
    def add_to_blacklist(self, ip_address: str, reason: str = None) -> bool:
        """Synchronous wrapper to add to blacklist."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        if loop.is_running():
            asyncio.create_task(self.add_to_blacklist_async(ip_address, reason))
            self._cache.add(ip_address)  # Optimistic update
            return True
        else:
            result = loop.run_until_complete(self.add_to_blacklist_async(ip_address, reason))
            return result
    
    def get_blacklist(self) -> List[str]:
        """Get current blacklist (from cache)."""
        if not self._cache_loaded:
            self.load_blacklist()
        return list(self._cache)
    
    def __contains__(self, item: str) -> bool:
        """Support 'in' operator for compatibility."""
        return self.is_blacklisted(item)
    
    def append(self, ip_address: str):
        """Support list.append() for compatibility."""
        self.add_to_blacklist(ip_address, reason="Auto-added by IDS")
    
    async def refresh_cache_async(self):
        """Refresh the cache from database."""
        await self.load_blacklist_async()


# Global instance
blacklist_manager = DatabaseBlacklistManager()

