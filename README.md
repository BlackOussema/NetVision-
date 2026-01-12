# 🔍 NetVision: Network Discovery & Asset Monitoring

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)

## Overview

NetVision is a lightweight yet powerful network discovery and asset monitoring tool. It combines active ARP scanning with passive packet sniffing to maintain a real-time inventory of all network devices. This tool is designed to help network administrators and security professionals keep track of devices connected to their network, monitor their status, and identify potential anomalies.

## Features

### Network Discovery
*   **Active ARP Scanning**: Fast and efficient discovery of live hosts on local networks.
*   **Passive Sniffing**: Non-intrusive monitoring of network traffic to detect devices without active scanning.
*   **MAC Vendor Lookup**: Automatic identification of device manufacturers based on MAC addresses.
*   **IPv4/IPv6 Support**: Compatible with both IPv4 and IPv6 network environments.

### REST API
*   **Full CRUD Operations**: Provides a RESTful API for creating, reading, updating, and deleting device information.
*   **Token Authentication**: Secure API access using bearer tokens to protect sensitive network data.
*   **Filtering & Pagination**: Efficient data retrieval with options for filtering and pagination.
*   **Statistics Endpoint**: Offers network overview and analytics, including device counts and status.

### Device Management
*   **Real-time Inventory**: Maintain an up-to-date inventory of all connected devices.
*   **Online/Offline Status**: Monitor device availability and track their online/offline status.
*   **Historical Data**: Record first seen and last seen timestamps for each device.
*   **Custom Metadata**: Ability to store additional custom information for each device.

## Quick Start

### Prerequisites
*   Python 3.8+
*   Root/sudo privileges (required for network scanning and sniffing functionalities).
*   Linux operating system (recommended for optimal performance and compatibility).

### Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/BlackOussema/NetVision-.git
    cd NetVision-
    ```

2.  **Create a virtual environment (recommended)**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Linux/macOS
    # .\venv\Scripts\activate   # On Windows
    ```

3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

### Running the API Server

```bash
# Start the Flask server
python3 app.py

# With custom configuration (e.g., port)
PORT=8080 python3 app.py

# With API token authentication
NETVISION_API_TOKEN=your-secret-token python3 app.py
```

### Running a Network Scan

```bash
# Basic ARP scan (requires root privileges)
sudo python3 scanner.py 192.168.1.0/24

# With custom timeout
sudo python3 scanner.py 192.168.1.0/24 --timeout 5

# Passive sniffing mode (requires root privileges)
sudo python3 scanner.py --passive --duration 120

# Scan without sending results to the API
sudo python3 scanner.py 192.168.1.0/24 --no-api
```

## API Reference

### Base URL
`http://localhost:5000/api`

### Authentication
Include the API token in your requests using either the `Authorization` header (Bearer token) or `X-API-Token` header:

```bash
# Using Authorization header
curl -H "Authorization: Bearer your-token" http://localhost:5000/api/devices

# Using X-API-Token header
curl -H "X-API-Token: your-token" http://localhost:5000/api/devices
```

### Endpoints

#### List All Devices
`GET /api/devices`

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `online` | boolean | Filter devices by online status |
| `limit` | integer | Maximum number of results to return |
| `offset` | integer | Pagination offset for results |

**Response Example**:
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
`GET /api/devices/{id}`

#### Add/Update Device
`POST /api/device`

**Request Body Example**:
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
`DELETE /api/device/{id}`

#### Get Statistics
`GET /api/stats`

**Response Example**:
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
`POST /api/devices/mark-offline`

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///netvision.db` | Database connection string (e.g., for SQLite, PostgreSQL, MySQL) |
| `NETVISION_API_TOKEN` | *(empty)* | API authentication token for secure access |
| `PORT` | `5000` | Port on which the API server will listen |
| `HOST` | `0.0.0.0` | Host address for the API server |
| `DEBUG` | `false` | Enable debug mode for development (set to `true` for verbose logging) |
| `NETVISION_API` | `http://127.0.0.1:5000/api/device` | API URL used by the scanner to send results |

### Database Options

NetVision supports various database backends. Configure `DATABASE_URL` in your environment:

```bash
# SQLite (default, file-based database)
export DATABASE_URL="sqlite:///netvision.db"

# PostgreSQL
export DATABASE_URL="postgresql://user:pass@localhost/netvision"

# MySQL
export DATABASE_URL="mysql://user:pass@localhost/netvision"
```

## Project Structure

```
NetVision/
├── app.py              # Flask API server application
├── scanner.py          # Network scanner script (ARP/passive modes)
├── models.py           # SQLAlchemy database models definition
├── requirements.txt    # Python dependencies list
├── README.md           # Project documentation (this file)
└── LICENSE             # MIT License file
```

## Scanner Options

```
usage: scanner.py [-h] [--timeout TIMEOUT] [--retry RETRY] [--passive]
                  [--duration DURATION] [--interface INTERFACE] [--no-api]
                  [--api-url API_URL] [-v] [--version]
                  [network]

Options:
  network               Network to scan (in CIDR notation, e.g., 192.168.1.0/24)
  --timeout TIMEOUT     Scan timeout in seconds (default: 3)
  --retry RETRY         Number of retries for host discovery (default: 2)
  --passive             Enable passive sniffing mode for device detection
  --duration DURATION   Duration in seconds for passive sniffing (default: 60)
  --interface, -i       Network interface to use for sniffing (e.g., eth0)
  --no-api              Do not send scan results to the API server
  --api-url             Custom API URL to send scan results to
  -v, --verbose         Enable verbose output for detailed logging
  --version             Show the tool's version and exit
```

## Docker Deployment

NetVision can be easily deployed using Docker. Example `Dockerfile` and `docker-compose.yml`:

### `Dockerfile`
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["python", "app.py"]
```

### `docker-compose.yml`
```yaml
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

## Security Considerations

*   **Root Privileges**: Network scanning and sniffing functionalities often require root privileges. Exercise caution and ensure proper permissions.
*   **API Token**: Always use a strong API authentication token in production environments to prevent unauthorized access to your network data.
*   **Network Segmentation**: Only scan and monitor networks for which you have explicit authorization. Avoid scanning external or unauthorized networks.
*   **Data Privacy**: Device information collected by NetVision may be sensitive. Ensure proper handling and storage of this data in compliance with privacy regulations.

## Contributing

Contributions are welcome! If you have suggestions for improvements, new features, or bug fixes, please feel free to open an issue or submit a pull request.

## Legal Disclaimer

**Only scan networks you own or have explicit permission to monitor.**

Unauthorized network scanning or monitoring may violate laws and regulations. The authors are not responsible for any misuse of this tool. Always ensure you have the necessary legal authorization before using NetVision.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for full details.

## Author

**Ghariani Oussema**
*   GitHub: [@BlackOussema](https://github.com/BlackOussema)
*   Role: Cybersecurity Researcher & Full-Stack Developer

---

<p align="center">
  Made with ❤️ in Tunisia 🇹🇳
</p>
