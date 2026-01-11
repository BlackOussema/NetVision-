<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Flask-2.0+-green.svg" alt="Flask">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux-lightgrey.svg" alt="Platform">
</p>

<h1 align="center">🔍 NetVision</h1>

<p align="center">
  <strong>Professional Network Discovery & Asset Monitoring</strong>
</p>

<p align="center">
  A lightweight yet powerful network discovery tool that combines active ARP scanning<br>
  with passive packet sniffing to maintain a real-time inventory of all network devices.
</p>

---

## ✨ Features

### Network Discovery
- **Active ARP Scanning** - Fast discovery of live hosts on local networks
- **Passive Sniffing** - Non-intrusive traffic monitoring for device detection
- **MAC Vendor Lookup** - Automatic identification of device manufacturers
- **IPv4/IPv6 Support** - Works with both IP versions

### REST API
- **Full CRUD Operations** - Create, read, update, delete devices
- **Token Authentication** - Secure API access with bearer tokens
- **Filtering & Pagination** - Efficient data retrieval
- **Statistics Endpoint** - Network overview and analytics

### Device Management
- **Real-time Inventory** - Track all connected devices
- **Online/Offline Status** - Monitor device availability
- **Historical Data** - First seen and last seen timestamps
- **Custom Metadata** - Store additional device information

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Root/sudo privileges (for network scanning)
- Linux operating system (recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/BlackOussema/NetVision-.git
cd NetVision-

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running the API Server

```bash
# Start the server
python3 app.py

# With custom configuration
PORT=8080 python3 app.py

# With API token authentication
NETVISION_API_TOKEN=your-secret-token python3 app.py
```

### Running a Network Scan

```bash
# Basic ARP scan (requires root)
sudo python3 scanner.py 192.168.1.0/24

# With custom timeout
sudo python3 scanner.py 192.168.1.0/24 --timeout 5

# Passive sniffing mode
sudo python3 scanner.py --passive --duration 120

# Scan without sending to API
sudo python3 scanner.py 192.168.1.0/24 --no-api
```

---

## 📡 API Reference

### Base URL
```
http://localhost:5000/api
```

### Authentication
Include the API token in requests:
```bash
# Using Authorization header
curl -H "Authorization: Bearer your-token" http://localhost:5000/api/devices

# Using X-API-Token header
curl -H "X-API-Token: your-token" http://localhost:5000/api/devices
```

### Endpoints

#### List All Devices
```http
GET /api/devices
```

Query Parameters:
| Parameter | Type | Description |
|-----------|------|-------------|
| `online` | boolean | Filter by online status |
| `limit` | integer | Maximum results to return |
| `offset` | integer | Pagination offset |

Response:
```json
{
  "count": 5,
  "devices": [
    {
      "id": 1,
      "ip": "192.168.1.100",
      "mac": "AA:BB:CC:DD:EE:FF",
      "hostname": "workstation-01",
      "vendor": "Dell",
      "device_type": "workstation",
      "first_seen": "2024-01-15T10:30:00",
      "last_seen": "2024-01-15T14:45:00",
      "is_online": true,
      "info": {}
    }
  ]
}
```

#### Get Single Device
```http
GET /api/devices/{id}
```

#### Add/Update Device
```http
POST /api/device
```

Request Body:
```json
{
  "ip": "192.168.1.100",
  "mac": "AA:BB:CC:DD:EE:FF",
  "hostname": "workstation-01",
  "vendor": "Dell",
  "device_type": "workstation",
  "info": {"location": "Office A"}
}
```

#### Delete Device
```http
DELETE /api/device/{id}
```

#### Get Statistics
```http
GET /api/stats
```

Response:
```json
{
  "total_devices": 25,
  "online_devices": 18,
  "offline_devices": 7,
  "device_types": {
    "workstation": 15,
    "router": 2,
    "printer": 3
  },
  "vendors": {
    "Dell": 10,
    "HP": 5,
    "Apple": 3
  }
}
```

#### Mark All Offline
```http
POST /api/devices/mark-offline
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///netvision.db` | Database connection string |
| `NETVISION_API_TOKEN` | *(empty)* | API authentication token |
| `PORT` | `5000` | Server port |
| `HOST` | `0.0.0.0` | Server host |
| `DEBUG` | `false` | Enable debug mode |
| `NETVISION_API` | `http://127.0.0.1:5000/api/device` | API URL for scanner |

### Database Options

```bash
# SQLite (default)
export DATABASE_URL="sqlite:///netvision.db"

# PostgreSQL
export DATABASE_URL="postgresql://user:pass@localhost/netvision"

# MySQL
export DATABASE_URL="mysql://user:pass@localhost/netvision"
```

---

## 📁 Project Structure

```
NetVision/
├── app.py              # Flask API server
├── scanner.py          # Network scanner (ARP/passive)
├── models.py           # SQLAlchemy database models
├── requirements.txt    # Python dependencies
├── README.md           # Documentation
└── LICENSE             # MIT License
```

---

## 🔧 Scanner Options

```
usage: scanner.py [-h] [--timeout TIMEOUT] [--retry RETRY] [--passive]
                  [--duration DURATION] [--interface INTERFACE] [--no-api]
                  [--api-url API_URL] [-v] [--version]
                  [network]

Options:
  network               Network to scan (CIDR notation)
  --timeout TIMEOUT     Scan timeout in seconds (default: 3)
  --retry RETRY         Number of retries (default: 2)
  --passive             Use passive sniffing mode
  --duration DURATION   Passive sniff duration (default: 60)
  --interface, -i       Network interface for sniffing
  --no-api              Don't send results to API
  --api-url             Custom API URL
  -v, --verbose         Enable verbose output
  --version             Show version
```

---

## 🐳 Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["python", "app.py"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  netvision:
    build: .
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=sqlite:///data/netvision.db
      - NETVISION_API_TOKEN=your-secret-token
    volumes:
      - ./data:/app/data
```

---

## 🔒 Security Considerations

- **Root Privileges**: Network scanning requires root access
- **API Token**: Always use authentication in production
- **Network Segmentation**: Only scan networks you're authorized to monitor
- **Data Privacy**: Device information may be sensitive

---

## 📋 Requirements

```
Flask>=2.0.0
Flask-CORS>=3.0.0
SQLAlchemy>=1.4.0
requests>=2.28.0
scapy>=2.5.0
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## ⚠️ Legal Disclaimer

**Only scan networks you own or have explicit permission to monitor.**

Unauthorized network scanning may violate laws and regulations. The authors are not responsible for misuse of this tool.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Ghariani Oussema**
- GitHub: [@BlackOussema](https://github.com/BlackOussema)
- Role: Cyber Security Researcher & Full-Stack Developer

---

<p align="center">
  Made with ❤️ in Tunisia 🇹🇳
</p>
