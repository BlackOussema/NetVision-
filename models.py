"""
NetVision Database Models

SQLAlchemy models for network device inventory.

Author: Ghariani Oussema
License: MIT
"""

from datetime import datetime
from typing import Optional, Dict, Any

from sqlalchemy import Column, Integer, String, DateTime, JSON, Boolean, Index
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Device(Base):
    """
    Network device model.
    
    Stores information about discovered network devices including
    IP address, MAC address, vendor information, and discovery metadata.
    """
    __tablename__ = "devices"
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Network identifiers
    ip = Column(String(45), nullable=False, index=True)  # IPv4 or IPv6
    mac = Column(String(17), nullable=False, unique=True, index=True)
    
    # Device information
    hostname = Column(String(255), nullable=True)
    vendor = Column(String(255), nullable=True)
    device_type = Column(String(100), nullable=True)  # router, switch, workstation, etc.
    
    # Timestamps
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Status
    is_online = Column(Boolean, default=True, nullable=False)
    
    # Additional metadata (JSON)
    info = Column(JSON, default=dict)
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_device_online', 'is_online'),
        Index('idx_device_last_seen', 'last_seen'),
        Index('idx_device_vendor', 'vendor'),
    )
    
    def __repr__(self) -> str:
        return f"<Device(id={self.id}, ip='{self.ip}', mac='{self.mac}', hostname='{self.hostname}')>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return {
            "id": self.id,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "is_online": self.is_online,
            "info": self.info or {}
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Device":
        """Create model from dictionary."""
        return cls(
            ip=data.get("ip"),
            mac=data.get("mac"),
            hostname=data.get("hostname"),
            vendor=data.get("vendor"),
            device_type=data.get("device_type"),
            info=data.get("info", {})
        )


class ScanHistory(Base):
    """
    Scan history model.
    
    Tracks network scan operations for auditing and analysis.
    """
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Scan details
    network = Column(String(50), nullable=False)  # CIDR notation
    scan_type = Column(String(50), nullable=False)  # arp, passive, ping
    
    # Results
    devices_found = Column(Integer, default=0)
    new_devices = Column(Integer, default=0)
    
    # Timing
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    
    # Status
    status = Column(String(50), default="running")  # running, completed, failed
    error_message = Column(String(500), nullable=True)
    
    def __repr__(self) -> str:
        return f"<ScanHistory(id={self.id}, network='{self.network}', status='{self.status}')>"
