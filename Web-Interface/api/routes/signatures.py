"""
Signature management endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
import yaml
import os

from ..models.database import get_db
from ..models.schemas import (
    SignatureResponse, SignatureCreate, SignatureUpdate
)
from ..models import crud

router = APIRouter(prefix="/signatures", tags=["signatures"])


@router.get("", response_model=List[SignatureResponse])
async def get_signatures(
    enabled_only: bool = False,
    db: AsyncSession = Depends(get_db)
):
    """Get all signatures."""
    signatures = await crud.get_signatures(db, enabled_only=enabled_only)
    return [
        SignatureResponse(
            id=sig.id,
            name=sig.name,
            pattern=sig.pattern,
            action=sig.action,
            description=sig.description,
            enabled=sig.enabled,
            created_at=sig.created_at,
            updated_at=sig.updated_at
        )
        for sig in signatures
    ]


@router.get("/{sig_id}", response_model=SignatureResponse)
async def get_signature(
    sig_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get a signature by ID."""
    signature = await crud.get_signature_by_id(db, sig_id)
    if not signature:
        raise HTTPException(status_code=404, detail="Signature not found")
    
    return SignatureResponse(
        id=signature.id,
        name=signature.name,
        pattern=signature.pattern,
        action=signature.action,
        description=signature.description,
        enabled=signature.enabled,
        created_at=signature.created_at,
        updated_at=signature.updated_at
    )


@router.post("", response_model=SignatureResponse, status_code=201)
async def create_signature(
    signature: SignatureCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create a new signature."""
    # Check if name already exists
    existing = await crud.get_signature_by_name(db, signature.name)
    if existing:
        raise HTTPException(status_code=400, detail="Signature name already exists")
    
    sig_data = signature.dict()
    new_sig = await crud.create_signature(db, sig_data)
    
    return SignatureResponse(
        id=new_sig.id,
        name=new_sig.name,
        pattern=new_sig.pattern,
        action=new_sig.action,
        description=new_sig.description,
        enabled=new_sig.enabled,
        created_at=new_sig.created_at,
        updated_at=new_sig.updated_at
    )


@router.put("/{sig_id}", response_model=SignatureResponse)
async def update_signature(
    sig_id: int,
    signature: SignatureUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update a signature."""
    update_data = signature.dict(exclude_unset=True)
    
    # If name is being updated, check for conflicts
    if "name" in update_data:
        existing = await crud.get_signature_by_name(db, update_data["name"])
        if existing and existing.id != sig_id:
            raise HTTPException(status_code=400, detail="Signature name already exists")
    
    updated = await crud.update_signature(db, sig_id, update_data)
    if not updated:
        raise HTTPException(status_code=404, detail="Signature not found")
    
    return SignatureResponse(
        id=updated.id,
        name=updated.name,
        pattern=updated.pattern,
        action=updated.action,
        description=updated.description,
        enabled=updated.enabled,
        created_at=updated.created_at,
        updated_at=updated.updated_at
    )


@router.delete("/{sig_id}")
async def delete_signature(
    sig_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Delete a signature."""
    success = await crud.delete_signature(db, sig_id)
    if not success:
        raise HTTPException(status_code=404, detail="Signature not found")
    return {"message": "Signature deleted successfully"}


@router.post("/reload")
async def reload_signatures(
    yaml_file: str = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Reload signatures from YAML file to database.
    This syncs YAML file -> database.
    """
    # Get default YAML file path
    if not yaml_file:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_dir))))
        yaml_file = os.path.join(project_root, "Configs", "test_yaml_file.yaml")
    
    if not os.path.exists(yaml_file):
        raise HTTPException(status_code=404, detail=f"YAML file not found: {yaml_file}")
    
    try:
        from integration.signature_manager import signature_manager
        signature_manager.yaml_file_path = yaml_file
        loaded_count = await signature_manager.sync_yaml_to_db_async()
        
        return {
            "message": f"Reloaded {loaded_count} signatures from {yaml_file}",
            "count": loaded_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reloading signatures: {str(e)}")


@router.post("/sync-to-yaml")
async def sync_signatures_to_yaml(
    db: AsyncSession = Depends(get_db)
):
    """
    Sync signatures from database to YAML file.
    This makes database signatures available to the IDS.
    After syncing, the IDS needs to reload its signatures.
    """
    try:
        from integration.signature_manager import signature_manager
        count = await signature_manager.sync_db_to_yaml_async()
        
        return {
            "message": f"Synced {count} signatures from database to YAML file",
            "count": count,
            "yaml_file": signature_manager.yaml_file_path,
            "note": "IDS needs to reload signatures to use the updated YAML file"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error syncing signatures: {str(e)}")

