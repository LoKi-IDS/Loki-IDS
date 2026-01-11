"""
Database models and connection for Loki IDS Web Interface.
Uses SQLite for lightweight, file-based storage.
"""
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, Text, DateTime, Index
from datetime import datetime

# Get project root directory
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
db_path = os.path.join(project_root, "Web-Interface", "loki_ids.db")

# Create async engine for SQLite
DATABASE_URL = f"sqlite+aiosqlite:///{db_path}"
engine = create_async_engine(DATABASE_URL, echo=False, future=True)

# Session factory
AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()


class Alert(Base):
    """Alert/Event records from IDS detection."""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, nullable=False, index=True)
    type = Column(String, nullable=False, index=True)  # SIGNATURE, BEHAVIOR, BLACKLIST
    src_ip = Column(String, nullable=False, index=True)
    dst_ip = Column(String, index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    message = Column(Text, nullable=False)
    details = Column(Text)  # JSON string
    severity = Column(String, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    
    __table_args__ = (
        Index('idx_timestamp', 'timestamp'),
        Index('idx_src_ip', 'src_ip'),
        Index('idx_type', 'type'),
    )


class BlacklistEntry(Base):
    """IP addresses in the blacklist."""
    __tablename__ = "blacklist"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, nullable=False, index=True)
    added_at = Column(String, nullable=False)
    added_by = Column(String, default="system")  # 'system' or 'user'
    reason = Column(Text)
    active = Column(Integer, default=1)  # 1 = active, 0 = removed


class Signature(Base):
    """Signature rules for detection."""
    __tablename__ = "signatures"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    pattern = Column(Text, nullable=False)
    action = Column(String, nullable=False)  # 'drop' or 'alert'
    description = Column(Text)
    enabled = Column(Integer, default=1)  # 1 = enabled, 0 = disabled
    created_at = Column(String)
    updated_at = Column(String)


class StatsCache(Base):
    """Cached statistics for performance."""
    __tablename__ = "stats_cache"
    
    key = Column(String, primary_key=True)
    value = Column(Text)  # JSON string
    updated_at = Column(String)


async def init_db():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    """Dependency for getting database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


