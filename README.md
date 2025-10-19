# NetVision

**NetVision** is a professional network and asset monitoring tool built with Python. It discovers devices on your network using **active ARP scanning** and **passive packet sniffing**, providing a real-time inventory of all connected assets. It also exposes a **RESTful API** and a **web interface** for monitoring.

---

## Features

- Active ARP scanning to detect live devices
- Passive packet sniffing for traffic analysis
- Real-time inventory of network devices
- Web interface for monitoring
- REST API for automation and integrations
- Works on Linux (tested on Kali Linux)

---

## Installation

1. **Clone the repository**
```bash
git clone https://github.com/BlackOussema/NetVision-.git
cd NetVision

2.Create a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate    # On Windows: .venv\Scripts\activate

3.Install dependencies
pip install -r requirements.txt

4.Optional: Environment configuration
Copy .env.example to .env if exists: cp .env.example .env
nano .env   # Edit variables if needed

5.Run the backend server
python3 backend/app.py
The server will start on http://127.0.0.1:5000 and http://<your-local-IP>:5000.

6.Access the API
curl http://127.0.0.1:5000/api/devices | jq .

7.Access the Web Interface
Open your browser and navigate to: http://127.0.0.1:5000

8.Requirements

Python 3.10+

Flask

SQLAlchemy

Scapy

Requests

All required packages are in requirements.txt.
                                                                        NOTES: Always run the tool inside a virtual environment (.venv) to avoid dependency conflicts.

                                                                                Make sure you have root privileges for ARP scanning if needed.

                                                                                       Tested on Kali Linux for full functionality.
                                                                                           DEVELOPER NAME:" Ghariani Oussema"
                                                                                             DEVELOPER INSTAGRAM:" mark.spongebob"
                                   
