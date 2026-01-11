"""
Alert management endpoints.
"""
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
import json

from ..models.database import get_db
from ..models.schemas import AlertResponse, AlertListResponse
from ..models import crud

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertListResponse)
async def get_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    alert_type: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    """Get alerts with filtering and pagination."""
    skip = (page - 1) * page_size
    alerts, total = await crud.get_alerts(
        db=db,
        skip=skip,
        limit=page_size,
        alert_type=alert_type,
        src_ip=src_ip,
        start_time=start_time,
        end_time=end_time
    )
    
    # Parse details JSON strings
    alert_list = []
    for alert in alerts:
        alert_dict = {
            "id": alert.id,
            "timestamp": alert.timestamp,
            "type": alert.type,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "src_port": alert.src_port,
            "dst_port": alert.dst_port,
            "message": alert.message,
            "details": json.loads(alert.details) if alert.details else {},
            "severity": alert.severity
        }
        alert_list.append(alert_dict)
    
    return AlertListResponse(
        alerts=alert_list,
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get a single alert by ID."""
    alert = await crud.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return AlertResponse(
        id=alert.id,
        timestamp=alert.timestamp,
        type=alert.type,
        src_ip=alert.src_ip,
        dst_ip=alert.dst_ip,
        src_port=alert.src_port,
        dst_port=alert.dst_port,
        message=alert.message,
        details=json.loads(alert.details) if alert.details else {},
        severity=alert.severity
    )


@router.delete("/{alert_id}")
async def delete_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Delete an alert."""
    success = await crud.delete_alert(db, alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"message": "Alert deleted successfully"}


