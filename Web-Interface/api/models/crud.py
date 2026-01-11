"""
CRUD operations for database models.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_
from sqlalchemy.orm import selectinload
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import json

from .database import Alert, BlacklistEntry, Signature, StatsCache


# Alert CRUD
async def create_alert(db: AsyncSession, alert_data: dict) -> Alert:
    """Create a new alert record."""
    alert = Alert(**alert_data)
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert


async def get_alerts(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 100,
    alert_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None
) -> tuple[List[Alert], int]:
    """Get alerts with filtering and pagination."""
    query = select(Alert)
    
    # Apply filters
    conditions = []
    if alert_type:
        conditions.append(Alert.type == alert_type)
    if src_ip:
        conditions.append(Alert.src_ip == src_ip)
    if start_time:
        conditions.append(Alert.timestamp >= start_time)
    if end_time:
        conditions.append(Alert.timestamp <= end_time)
    
    if conditions:
        query = query.where(and_(*conditions))
    
    # Get total count
    count_query = select(func.count()).select_from(Alert)
    if conditions:
        count_query = count_query.where(and_(*conditions))
    total = await db.scalar(count_query)
    
    # Apply pagination and ordering
    query = query.order_by(desc(Alert.timestamp)).offset(skip).limit(limit)
    result = await db.execute(query)
    alerts = result.scalars().all()
    
    return alerts, total


async def get_alert_by_id(db: AsyncSession, alert_id: int) -> Optional[Alert]:
    """Get a single alert by ID."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    return result.scalar_one_or_none()


async def delete_alert(db: AsyncSession, alert_id: int) -> bool:
    """Delete an alert."""
    alert = await get_alert_by_id(db, alert_id)
    if alert:
        await db.delete(alert)
        await db.commit()
        return True
    return False


# Blacklist CRUD
async def get_blacklist(db: AsyncSession, active_only: bool = True) -> List[BlacklistEntry]:
    """Get all blacklist entries."""
    query = select(BlacklistEntry)
    if active_only:
        query = query.where(BlacklistEntry.active == 1)
    query = query.order_by(desc(BlacklistEntry.added_at))
    result = await db.execute(query)
    return result.scalars().all()


async def get_blacklist_entry(db: AsyncSession, ip_address: str) -> Optional[BlacklistEntry]:
    """Get a blacklist entry by IP."""
    result = await db.execute(
        select(BlacklistEntry).where(BlacklistEntry.ip_address == ip_address)
    )
    return result.scalar_one_or_none()


async def add_to_blacklist(
    db: AsyncSession,
    ip_address: str,
    reason: Optional[str] = None,
    added_by: str = "user"
) -> BlacklistEntry:
    """Add an IP to the blacklist."""
    # Check if already exists
    existing = await get_blacklist_entry(db, ip_address)
    if existing:
        # Reactivate if it was removed
        if existing.active == 0:
            existing.active = 1
            existing.added_at = datetime.utcnow().isoformat()
            existing.reason = reason or existing.reason
            await db.commit()
            await db.refresh(existing)
            return existing
        return existing
    
    entry = BlacklistEntry(
        ip_address=ip_address,
        reason=reason,
        added_by=added_by,
        added_at=datetime.utcnow().isoformat(),
        active=1
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


async def remove_from_blacklist(db: AsyncSession, ip_address: str) -> bool:
    """Remove an IP from blacklist (soft delete)."""
    entry = await get_blacklist_entry(db, ip_address)
    if entry:
        entry.active = 0
        await db.commit()
        return True
    return False


# Signature CRUD
async def get_signatures(db: AsyncSession, enabled_only: bool = False) -> List[Signature]:
    """Get all signatures."""
    query = select(Signature)
    if enabled_only:
        query = query.where(Signature.enabled == 1)
    query = query.order_by(Signature.name)
    result = await db.execute(query)
    return result.scalars().all()


async def get_signature_by_id(db: AsyncSession, sig_id: int) -> Optional[Signature]:
    """Get a signature by ID."""
    result = await db.execute(select(Signature).where(Signature.id == sig_id))
    return result.scalar_one_or_none()


async def get_signature_by_name(db: AsyncSession, name: str) -> Optional[Signature]:
    """Get a signature by name."""
    result = await db.execute(select(Signature).where(Signature.name == name))
    return result.scalar_one_or_none()


async def create_signature(db: AsyncSession, sig_data: dict) -> Signature:
    """Create a new signature."""
    sig_data['created_at'] = datetime.utcnow().isoformat()
    signature = Signature(**sig_data)
    db.add(signature)
    await db.commit()
    await db.refresh(signature)
    return signature


async def update_signature(
    db: AsyncSession,
    sig_id: int,
    update_data: dict
) -> Optional[Signature]:
    """Update a signature."""
    signature = await get_signature_by_id(db, sig_id)
    if signature:
        update_data['updated_at'] = datetime.utcnow().isoformat()
        for key, value in update_data.items():
            setattr(signature, key, value)
        await db.commit()
        await db.refresh(signature)
        return signature
    return None


async def delete_signature(db: AsyncSession, sig_id: int) -> bool:
    """Delete a signature."""
    signature = await get_signature_by_id(db, sig_id)
    if signature:
        await db.delete(signature)
        await db.commit()
        return True
    return False


# Statistics
async def get_alert_stats(db: AsyncSession) -> Dict[str, Any]:
    """Get alert statistics."""
    # Total alerts
    total = await db.scalar(select(func.count(Alert.id)))
    
    # Alerts by type
    type_query = select(Alert.type, func.count(Alert.id)).group_by(Alert.type)
    type_result = await db.execute(type_query)
    alerts_by_type = {row[0]: row[1] for row in type_result.all()}
    
    # Top attacking IPs (last 24 hours)
    yesterday = (datetime.utcnow() - timedelta(days=1)).isoformat()
    top_ips_query = (
        select(Alert.src_ip, func.count(Alert.id).label('count'))
        .where(Alert.timestamp >= yesterday)
        .group_by(Alert.src_ip)
        .order_by(desc('count'))
        .limit(10)
    )
    top_ips_result = await db.execute(top_ips_query)
    top_attacking_ips = [
        {"ip": row[0], "count": row[1]} for row in top_ips_result.all()
    ]
    
    # Alerts in last 24 hours
    alerts_24h = await db.scalar(
        select(func.count(Alert.id)).where(Alert.timestamp >= yesterday)
    )
    
    # Alerts in last hour
    hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
    alerts_1h = await db.scalar(
        select(func.count(Alert.id)).where(Alert.timestamp >= hour_ago)
    )
    
    return {
        "total_alerts": total or 0,
        "alerts_by_type": alerts_by_type,
        "top_attacking_ips": top_attacking_ips,
        "alerts_last_24h": alerts_24h or 0,
        "alerts_last_hour": alerts_1h or 0
    }


