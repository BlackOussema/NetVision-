#!/usr/bin/env python3
"""
NetVision - Network Discovery & Asset Monitoring API

A professional Flask-based REST API for network device discovery
and asset inventory management.

Author: Ghariani Oussema
License: MIT
"""

import os
import logging
from datetime import datetime
from functools import wraps
from typing import Optional, Dict, Any, List

from flask import Flask, jsonify, request, abort, Response
from flask_cors import CORS
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker, Session as SQLSession

from models import Base, Device

# Configuration
VERSION = "1.0.0"
DB_URL = os.environ.get("DATABASE_URL", "sqlite:///netvision.db")
API_TOKEN = os.environ.get("NETVISION_API_TOKEN", "")
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

# Logging setup
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Database setup
engine = create_engine(DB_URL, echo=DEBUG, future=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base.metadata.create_all(engine)

# Flask app
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})


def get_db() -> SQLSession:
    """Get database session."""
    return SessionLocal()


def require_token(f):
    """Decorator to require API token authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not API_TOKEN:
            return f(*args, **kwargs)
        
        token = None
        auth_header = request.headers.get("Authorization", "")
        
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        
        if not token:
            token = request.headers.get("X-API-Token", "")
        
        if token != API_TOKEN:
            logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
            return jsonify({"error": "Unauthorized", "message": "Invalid or missing API token"}), 401
        
        return f(*args, **kwargs)
    return decorated


def device_to_dict(device: Device) -> Dict[str, Any]:
    """Convert Device model to dictionary."""
    return {
        "id": device.id,
        "ip": device.ip,
        "mac": device.mac,
        "hostname": device.hostname,
        "vendor": device.vendor,
        "device_type": device.device_type,
        "first_seen": device.first_seen.isoformat() if device.first_seen else None,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
        "is_online": device.is_online,
        "info": device.info or {}
    }


# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check() -> Response:
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "version": VERSION,
        "timestamp": datetime.utcnow().isoformat()
    })


# API Info
@app.route("/api", methods=["GET"])
def api_info() -> Response:
    """API information endpoint."""
    return jsonify({
        "name": "NetVision API",
        "version": VERSION,
        "endpoints": {
            "GET /api/devices": "List all discovered devices",
            "GET /api/devices/<id>": "Get device by ID",
            "POST /api/device": "Add or update a device",
            "DELETE /api/device/<id>": "Delete a device",
            "GET /api/stats": "Get network statistics",
            "POST /api/scan": "Trigger network scan"
        }
    })


# List all devices
@app.route("/api/devices", methods=["GET"])
def list_devices() -> Response:
    """
    List all discovered network devices.
    
    Query Parameters:
        - online: Filter by online status (true/false)
        - limit: Maximum number of results
        - offset: Pagination offset
    """
    db = get_db()
    try:
        query = db.query(Device)
        
        # Filter by online status
        online_filter = request.args.get("online")
        if online_filter is not None:
            is_online = online_filter.lower() == "true"
            query = query.filter(Device.is_online == is_online)
        
        # Sorting
        query = query.order_by(desc(Device.last_seen))
        
        # Pagination
        limit = request.args.get("limit", type=int)
        offset = request.args.get("offset", type=int, default=0)
        
        if limit:
            query = query.limit(limit).offset(offset)
        
        devices = query.all()
        
        return jsonify({
            "count": len(devices),
            "devices": [device_to_dict(d) for d in devices]
        })
    finally:
        db.close()


# Get single device
@app.route("/api/devices/<int:device_id>", methods=["GET"])
def get_device(device_id: int) -> Response:
    """Get a specific device by ID."""
    db = get_db()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        
        if not device:
            return jsonify({"error": "Device not found"}), 404
        
        return jsonify(device_to_dict(device))
    finally:
        db.close()


# Add or update device
@app.route("/api/device", methods=["POST"])
@require_token
def add_or_update_device() -> Response:
    """
    Add a new device or update existing one.
    
    Request Body:
        - ip: IP address (required)
        - mac: MAC address (required)
        - hostname: Device hostname (optional)
        - vendor: Device vendor (optional)
        - device_type: Type of device (optional)
        - info: Additional information (optional)
    """
    payload = request.get_json() or {}
    
    ip = payload.get("ip", "").strip()
    mac = payload.get("mac", "").strip().upper()
    
    if not ip or not mac:
        return jsonify({
            "error": "Validation error",
            "message": "Both 'ip' and 'mac' fields are required"
        }), 400
    
    # Validate MAC format
    if len(mac.replace(":", "").replace("-", "")) != 12:
        return jsonify({
            "error": "Validation error",
            "message": "Invalid MAC address format"
        }), 400
    
    db = get_db()
    try:
        now = datetime.utcnow()
        device = db.query(Device).filter(Device.mac == mac).first()
        
        if device:
            # Update existing device
            device.ip = ip
            device.hostname = payload.get("hostname", device.hostname)
            device.vendor = payload.get("vendor", device.vendor)
            device.device_type = payload.get("device_type", device.device_type)
            device.last_seen = now
            device.is_online = True
            
            if payload.get("info"):
                device.info = {**(device.info or {}), **payload["info"]}
            
            logger.info(f"Updated device: {mac} ({ip})")
            action = "updated"
        else:
            # Create new device
            device = Device(
                ip=ip,
                mac=mac,
                hostname=payload.get("hostname"),
                vendor=payload.get("vendor"),
                device_type=payload.get("device_type"),
                first_seen=now,
                last_seen=now,
                is_online=True,
                info=payload.get("info", {})
            )
            db.add(device)
            logger.info(f"Added new device: {mac} ({ip})")
            action = "created"
        
        db.commit()
        db.refresh(device)
        
        return jsonify({
            "status": "success",
            "action": action,
            "device": device_to_dict(device)
        }), 201 if action == "created" else 200
        
    except Exception as e:
        db.rollback()
        logger.error(f"Database error: {e}")
        return jsonify({"error": "Database error", "message": str(e)}), 500
    finally:
        db.close()


# Delete device
@app.route("/api/device/<int:device_id>", methods=["DELETE"])
@require_token
def delete_device(device_id: int) -> Response:
    """Delete a device by ID."""
    db = get_db()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        
        if not device:
            return jsonify({"error": "Device not found"}), 404
        
        db.delete(device)
        db.commit()
        
        logger.info(f"Deleted device: {device.mac}")
        return jsonify({"status": "success", "message": "Device deleted"})
        
    except Exception as e:
        db.rollback()
        logger.error(f"Delete error: {e}")
        return jsonify({"error": "Database error", "message": str(e)}), 500
    finally:
        db.close()


# Network statistics
@app.route("/api/stats", methods=["GET"])
def get_stats() -> Response:
    """Get network statistics."""
    db = get_db()
    try:
        total_devices = db.query(Device).count()
        online_devices = db.query(Device).filter(Device.is_online == True).count()
        
        # Get device types distribution
        devices = db.query(Device).all()
        device_types = {}
        vendors = {}
        
        for d in devices:
            if d.device_type:
                device_types[d.device_type] = device_types.get(d.device_type, 0) + 1
            if d.vendor:
                vendors[d.vendor] = vendors.get(d.vendor, 0) + 1
        
        return jsonify({
            "total_devices": total_devices,
            "online_devices": online_devices,
            "offline_devices": total_devices - online_devices,
            "device_types": device_types,
            "vendors": vendors
        })
    finally:
        db.close()


# Mark devices offline
@app.route("/api/devices/mark-offline", methods=["POST"])
@require_token
def mark_devices_offline() -> Response:
    """Mark all devices as offline (useful before a new scan)."""
    db = get_db()
    try:
        updated = db.query(Device).filter(Device.is_online == True).update(
            {"is_online": False}
        )
        db.commit()
        
        return jsonify({
            "status": "success",
            "devices_marked_offline": updated
        })
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


# Error handlers
@app.errorhandler(404)
def not_found(error) -> Response:
    return jsonify({"error": "Not found", "message": str(error)}), 404


@app.errorhandler(500)
def internal_error(error) -> Response:
    return jsonify({"error": "Internal server error", "message": str(error)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    
    logger.info(f"Starting NetVision API v{VERSION}")
    logger.info(f"Listening on {host}:{port}")
    logger.info(f"Database: {DB_URL}")
    logger.info(f"API Token: {'Enabled' if API_TOKEN else 'Disabled'}")
    
    app.run(host=host, port=port, debug=DEBUG)
