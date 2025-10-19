# backend/app.py
from flask import Flask, jsonify, request, abort
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Device
from datetime import datetime
import os

DB_URL = os.environ.get("DATABASE_URL", "sqlite:///netvision.db")
API_TOKEN = os.environ.get("NETVISION_API_TOKEN", "")  # read token from env

engine = create_engine(DB_URL, echo=False, future=True)
Session = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

app = Flask(__name__)

@app.route("/api/devices", methods=["GET"])
def list_devices():
    s = Session()
    devices = s.query(Device).order_by(Device.last_seen.desc()).all()
    data = [{
        "id": d.id,
        "ip": d.ip,
        "mac": d.mac,
        "hostname": d.hostname,
        "first_seen": d.first_seen.isoformat(),
        "last_seen": d.last_seen.isoformat(),
        "info": d.info
    } for d in devices]
    s.close()
    return jsonify(data)

def require_token():
    if API_TOKEN:
        token = None
        # first check Authorization header Bearer
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1].strip()
        # fallback: custom header X-API-Token
        if not token:
            token = request.headers.get("X-API-Token", "")
        if token != API_TOKEN:
            abort(401, description="Unauthorized")

@app.route("/api/device", methods=["POST"])
def add_device():
    # require token for POST
    require_token()

    payload = request.json or {}
    ip = payload.get("ip")
    mac = payload.get("mac")
    if not ip or not mac:
        return jsonify({"error": "ip and mac required"}), 400
    s = Session()
    dev = s.query(Device).filter_by(mac=mac).first()
    now = datetime.utcnow()
    if dev:
        dev.ip = ip
        dev.hostname = payload.get("hostname", dev.hostname)
        dev.last_seen = now
        dev.info = payload.get("info", dev.info)
    else:
        dev = Device(ip=ip, mac=mac, hostname=payload.get("hostname"),
                     first_seen=now, last_seen=now, info=payload.get("info", {}))
        s.add(dev)
    s.commit()
    s.close()
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
