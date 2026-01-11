"""
Signature manager that syncs between database and YAML file.
Handles bidirectional sync: database <-> YAML file.
"""
import yaml
import os
import sys
import asyncio
from typing import List, Dict, Any

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(project_root, "Web-Interface"))

from api.models.database import AsyncSessionLocal
from api.models import crud


class SignatureManager:
    """
    Manages signature synchronization between database and YAML file.
    """
    def __init__(self, yaml_file_path=None):
        if not yaml_file_path:
            yaml_file_path = os.path.join(project_root, "Configs", "test_yaml_file.yaml")
        self.yaml_file_path = yaml_file_path
    
    async def sync_db_to_yaml_async(self):
        """
        Sync signatures from database to YAML file.
        This makes database signatures available to the IDS.
        """
        try:
            async with AsyncSessionLocal() as session:
                signatures = await crud.get_signatures(session, enabled_only=True)
                
                # Convert to YAML format
                yaml_signatures = []
                for sig in signatures:
                    yaml_signatures.append({
                        'name': sig.name,
                        'pattern': sig.pattern,
                        'action': sig.action,
                        'description': sig.description or ''
                    })
                
                # Write to YAML file
                yaml_data = {'signatures': yaml_signatures}
                
                # Ensure directory exists
                os.makedirs(os.path.dirname(self.yaml_file_path), exist_ok=True)
                
                with open(self.yaml_file_path, 'w') as f:
                    yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False)
                
                return len(yaml_signatures)
        except Exception as e:
            print(f"[!] Error syncing database to YAML: {e}")
            raise
    
    def sync_db_to_yaml(self):
        """Synchronous wrapper for sync_db_to_yaml_async."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        if loop.is_running():
            # If loop is running, schedule as task
            asyncio.create_task(self.sync_db_to_yaml_async())
            return True
        else:
            return loop.run_until_complete(self.sync_db_to_yaml_async())
    
    async def sync_yaml_to_db_async(self):
        """
        Sync signatures from YAML file to database.
        This loads YAML signatures into the database.
        """
        try:
            if not os.path.exists(self.yaml_file_path):
                print(f"[!] YAML file not found: {self.yaml_file_path}")
                return 0
            
            with open(self.yaml_file_path, 'r') as f:
                all_rules = yaml.safe_load(f)
            
            signatures = all_rules.get('signatures', [])
            
            async with AsyncSessionLocal() as session:
                loaded_count = 0
                for sig_data in signatures:
                    existing = await crud.get_signature_by_name(session, sig_data['name'])
                    if existing:
                        # Update existing
                        await crud.update_signature(session, existing.id, {
                            'pattern': sig_data['pattern'],
                            'action': sig_data.get('action', 'alert'),
                            'description': sig_data.get('description', ''),
                            'enabled': 1
                        })
                    else:
                        # Create new
                        await crud.create_signature(session, {
                            'name': sig_data['name'],
                            'pattern': sig_data['pattern'],
                            'action': sig_data.get('action', 'alert'),
                            'description': sig_data.get('description', ''),
                            'enabled': 1
                        })
                    loaded_count += 1
                
                return loaded_count
        except Exception as e:
            print(f"[!] Error syncing YAML to database: {e}")
            raise


# Global instance
signature_manager = SignatureManager()


