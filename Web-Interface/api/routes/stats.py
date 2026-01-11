"""
Statistics and analytics endpoints.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.database import get_db
from ..models.schemas import StatsResponse
from ..models import crud

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("", response_model=StatsResponse)
async def get_stats(
    db: AsyncSession = Depends(get_db)
):
    """Get alert statistics."""
    stats = await crud.get_alert_stats(db)
    return StatsResponse(**stats)


