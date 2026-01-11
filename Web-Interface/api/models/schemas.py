"""
Pydantic schemas for API request/response validation.
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime


class AlertBase(BaseModel):
    timestamp: str
    type: str
    src_ip: str
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    message: str
    details: Optional[Dict[str, Any]] = None
    severity: Optional[str] = "MEDIUM"


class AlertCreate(AlertBase):
    pass


class AlertResponse(AlertBase):
    id: int
    
    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    alerts: List[AlertResponse]
    total: int
    page: int
    page_size: int


class BlacklistEntryBase(BaseModel):
    ip_address: str
    reason: Optional[str] = None
    added_by: Optional[str] = "user"
    
    @validator('ip_address')
    def validate_ip(cls, v):
        # Basic IP validation
        parts = v.split('.')
        if len(parts) != 4:
            raise ValueError('Invalid IP address format')
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                raise ValueError('Invalid IP address format')
        return v


class BlacklistEntryCreate(BlacklistEntryBase):
    pass


class BlacklistEntryResponse(BlacklistEntryBase):
    id: int
    added_at: str
    active: int
    
    class Config:
        from_attributes = True


class SignatureBase(BaseModel):
    name: str
    pattern: str
    action: str  # 'drop' or 'alert'
    description: Optional[str] = None
    enabled: Optional[int] = 1
    
    @validator('action')
    def validate_action(cls, v):
        if v not in ['drop', 'alert']:
            raise ValueError('Action must be "drop" or "alert"')
        return v


class SignatureCreate(SignatureBase):
    pass


class SignatureUpdate(BaseModel):
    name: Optional[str] = None
    pattern: Optional[str] = None
    action: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[int] = None


class SignatureResponse(SignatureBase):
    id: int
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    
    class Config:
        from_attributes = True


class SystemStatus(BaseModel):
    ids_running: bool
    uptime: Optional[str] = None
    packets_processed: Optional[int] = None
    alerts_count_24h: Optional[int] = None
    blacklist_size: Optional[int] = None


class StatsResponse(BaseModel):
    total_alerts: int
    alerts_by_type: Dict[str, int]
    top_attacking_ips: List[Dict[str, Any]]
    alerts_last_24h: int
    alerts_last_hour: int


class HealthResponse(BaseModel):
    status: str
    database: str
    timestamp: str


