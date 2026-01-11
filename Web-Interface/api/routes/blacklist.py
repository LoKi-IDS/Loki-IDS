"""
Blacklist management endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from ..models.database import get_db
from ..models.schemas import BlacklistEntryResponse, BlacklistEntryCreate
from ..models import crud

router = APIRouter(prefix="/blacklist", tags=["blacklist"])


@router.get("", response_model=List[BlacklistEntryResponse])
async def get_blacklist(
    active_only: bool = True,
    db: AsyncSession = Depends(get_db)
):
    """Get all blacklist entries."""
    entries = await crud.get_blacklist(db, active_only=active_only)
    return [
        BlacklistEntryResponse(
            id=entry.id,
            ip_address=entry.ip_address,
            reason=entry.reason,
            added_by=entry.added_by,
            added_at=entry.added_at,
            active=entry.active
        )
        for entry in entries
    ]


@router.post("", response_model=BlacklistEntryResponse, status_code=201)
async def add_to_blacklist(
    entry: BlacklistEntryCreate,
    db: AsyncSession = Depends(get_db)
):
    """Add an IP address to the blacklist."""
    new_entry = await crud.add_to_blacklist(
        db=db,
        ip_address=entry.ip_address,
        reason=entry.reason,
        added_by=entry.added_by
    )
    
    return BlacklistEntryResponse(
        id=new_entry.id,
        ip_address=new_entry.ip_address,
        reason=new_entry.reason,
        added_by=new_entry.added_by,
        added_at=new_entry.added_at,
        active=new_entry.active
    )


@router.delete("/{ip_address}")
async def remove_from_blacklist(
    ip_address: str,
    db: AsyncSession = Depends(get_db)
):
    """Remove an IP address from the blacklist."""
    success = await crud.remove_from_blacklist(db, ip_address)
    if not success:
        raise HTTPException(status_code=404, detail="IP address not found in blacklist")
    return {"message": f"IP {ip_address} removed from blacklist"}


