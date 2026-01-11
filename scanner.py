#!/usr/bin/env python3
"""
NetVision Network Scanner - Active & Passive Discovery

Performs network discovery using:
- ARP scanning for local network devices
- ICMP ping sweeps
- Passive packet sniffing

Author: Ghariani Oussema
License: MIT
"""

import argparse
import ipaddress
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any

import requests

try:
    from scapy.all import ARP, Ether, srp, conf, sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Configuration
VERSION = "1.0.0"
API_URL = os.environ.get("NETVISION_API", "http://127.0.0.1:5000/api/device")
API_TOKEN = os.environ.get("NETVISION_API_TOKEN", "")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# MAC vendor prefixes (common ones)
MAC_VENDORS = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:1A:79": "Apple",
    "00:1E:C2": "Apple",
    "3C:06:30": "Apple",
    "AC:DE:48": "Apple",
    "00:1A:2B": "Cisco",
    "00:1B:54": "Cisco",
    "00:25:B5": "Cisco",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:15:5D": "Microsoft Hyper-V",
    "00:1C:42": "Parallels",
    "00:16:3E": "Xen",
    "00:E0:4C": "Realtek",
    "00:1F:D0": "Giga-Byte",
    "00:24:8C": "ASUSTek",
    "00:26:B9": "Dell",
    "00:1E:68": "Quanta",
    "00:21:5A": "HP",
    "00:25:64": "Dell",
    "00:1A:A0": "Dell",
    "00:50:B6": "Linksys",
    "00:14:BF": "Linksys",
    "00:18:39": "Cisco-Linksys",
    "00:1D:7E": "Cisco-Linksys",
    "00:22:6B": "Cisco-Linksys",
    "00:1E:58": "D-Link",
    "00:22:B0": "D-Link",
    "00:26:5A": "D-Link",
    "00:1F:33": "Netgear",
    "00:22:3F": "Netgear",
    "00:26:F2": "Netgear",
    "00:1A:4D": "TP-Link",
    "00:27:19": "TP-Link",
    "50:C7:BF": "TP-Link",
    "00:1D:0F": "TP-Link",
}


@dataclass
class DiscoveredDevice:
    """Represents a discovered network device."""
    ip: str
    mac: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    response_time: Optional[float] = None


def get_mac_vendor(mac: str) -> Optional[str]:
    """Get vendor name from MAC address prefix."""
    mac_upper = mac.upper().replace("-", ":")
    prefix = mac_upper[:8]
    return MAC_VENDORS.get(prefix)


def check_root() -> bool:
    """Check if running with root privileges."""
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else True


class NetworkScanner:
    """Network scanner with multiple discovery methods."""
    
    def __init__(self, timeout: int = 3, retry: int = 2):
        self.timeout = timeout
        self.retry = retry
        
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required. Install with: pip install scapy")
        
        conf.verb = 0  # Disable scapy verbosity
    
    def arp_scan(self, network: str) -> List[DiscoveredDevice]:
        """
        Perform ARP scan on the specified network.
        
        Args:
            network: Network in CIDR notation (e.g., 192.168.1.0/24)
        
        Returns:
            List of discovered devices
        """
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            logger.error(f"Invalid network CIDR: {e}")
            return []
        
        logger.info(f"Starting ARP scan on {network}")
        
        # Create ARP request packet
        arp_request = ARP(pdst=str(net))
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        
        # Send and receive
        start_time = time.time()
        answered, _ = srp(packet, timeout=self.timeout, retry=self.retry)
        scan_time = time.time() - start_time
        
        devices = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc.upper()
            vendor = get_mac_vendor(mac)
            
            device = DiscoveredDevice(
                ip=ip,
                mac=mac,
                vendor=vendor,
                response_time=scan_time
            )
            devices.append(device)
            logger.debug(f"Found: {ip} ({mac}) - {vendor or 'Unknown vendor'}")
        
        logger.info(f"ARP scan complete: {len(devices)} devices found in {scan_time:.2f}s")
        return devices
    
    def passive_sniff(
        self,
        interface: Optional[str] = None,
        duration: int = 60,
        filter_str: str = "arp or icmp"
    ) -> List[DiscoveredDevice]:
        """
        Passively sniff network traffic to discover devices.
        
        Args:
            interface: Network interface to sniff on
            duration: Duration in seconds
            filter_str: BPF filter string
        
        Returns:
            List of discovered devices
        """
        logger.info(f"Starting passive sniff for {duration}s")
        
        discovered = {}
        
        def packet_handler(packet):
            if ARP in packet:
                ip = packet[ARP].psrc
                mac = packet[ARP].hwsrc.upper()
                if ip and mac and ip != "0.0.0.0":
                    discovered[mac] = DiscoveredDevice(
                        ip=ip,
                        mac=mac,
                        vendor=get_mac_vendor(mac)
                    )
            elif IP in packet:
                ip = packet[IP].src
                if hasattr(packet, 'src') and packet.src:
                    mac = packet.src.upper()
                    if ip and mac:
                        discovered[mac] = DiscoveredDevice(
                            ip=ip,
                            mac=mac,
                            vendor=get_mac_vendor(mac)
                        )
        
        try:
            sniff(
                iface=interface,
                filter=filter_str,
                prn=packet_handler,
                timeout=duration,
                store=False
            )
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
        
        devices = list(discovered.values())
        logger.info(f"Passive sniff complete: {len(devices)} devices discovered")
        return devices


class APIClient:
    """Client for NetVision API."""
    
    def __init__(self, api_url: str = API_URL, api_token: str = API_TOKEN):
        self.api_url = api_url.rstrip("/")
        self.api_token = api_token
        self.session = requests.Session()
        
        if api_token:
            self.session.headers["Authorization"] = f"Bearer {api_token}"
    
    def post_device(self, device: DiscoveredDevice) -> bool:
        """Send discovered device to API."""
        payload = {
            "ip": device.ip,
            "mac": device.mac,
            "hostname": device.hostname,
            "vendor": device.vendor,
            "device_type": device.device_type,
            "info": {
                "source": "scanner",
                "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "response_time": device.response_time
            }
        }
        
        try:
            response = self.session.post(
                f"{self.api_url}/device",
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            logger.warning(f"API error for {device.ip}: {e}")
            return False
    
    def mark_all_offline(self) -> bool:
        """Mark all devices as offline before scan."""
        try:
            response = self.session.post(
                f"{self.api_url}/devices/mark-offline",
                timeout=10
            )
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            logger.warning(f"Failed to mark devices offline: {e}")
            return False


def print_results(devices: List[DiscoveredDevice]) -> None:
    """Print scan results in a formatted table."""
    if not devices:
        print("\nNo devices found.")
        return
    
    print(f"\n{'='*70}")
    print(f"{'IP Address':<18} {'MAC Address':<20} {'Vendor':<30}")
    print(f"{'='*70}")
    
    for device in sorted(devices, key=lambda d: ipaddress.ip_address(d.ip)):
        vendor = device.vendor or "Unknown"
        print(f"{device.ip:<18} {device.mac:<20} {vendor:<30}")
    
    print(f"{'='*70}")
    print(f"Total: {len(devices)} devices found\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="NetVision Network Scanner - Discover devices on your network",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24
  %(prog)s 10.0.0.0/24 --timeout 5
  %(prog)s 192.168.1.0/24 --no-api
  %(prog)s --passive --duration 120
        """
    )
    parser.add_argument(
        "network",
        nargs="?",
        help="Network to scan in CIDR notation (e.g., 192.168.1.0/24)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=3,
        help="Scan timeout in seconds (default: 3)"
    )
    parser.add_argument(
        "--retry",
        type=int,
        default=2,
        help="Number of retries (default: 2)"
    )
    parser.add_argument(
        "--passive",
        action="store_true",
        help="Use passive sniffing instead of active scanning"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Passive sniff duration in seconds (default: 60)"
    )
    parser.add_argument(
        "--interface",
        "-i",
        help="Network interface for passive sniffing"
    )
    parser.add_argument(
        "--no-api",
        action="store_true",
        help="Don't send results to API"
    )
    parser.add_argument(
        "--api-url",
        default=API_URL,
        help=f"API URL (default: {API_URL})"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"NetVision Scanner v{VERSION}"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Check for root privileges
    if not check_root():
        logger.error("This script requires root privileges. Run with sudo.")
        sys.exit(1)
    
    # Check scapy
    if not SCAPY_AVAILABLE:
        logger.error("Scapy is not installed. Install with: pip install scapy")
        sys.exit(1)
    
    # Get network if not provided
    if not args.network and not args.passive:
        args.network = input("Enter network CIDR (e.g., 192.168.1.0/24): ").strip()
    
    # Validate network
    if args.network:
        try:
            ipaddress.ip_network(args.network, strict=False)
        except ValueError as e:
            logger.error(f"Invalid network CIDR: {e}")
            sys.exit(1)
    
    # Initialize scanner
    scanner = NetworkScanner(timeout=args.timeout, retry=args.retry)
    
    # Perform scan
    if args.passive:
        devices = scanner.passive_sniff(
            interface=args.interface,
            duration=args.duration
        )
    else:
        devices = scanner.arp_scan(args.network)
    
    # Print results
    print_results(devices)
    
    # Send to API
    if not args.no_api and devices:
        logger.info("Sending results to API...")
        client = APIClient(api_url=args.api_url)
        
        # Mark existing devices offline first
        client.mark_all_offline()
        
        success = 0
        for device in devices:
            if client.post_device(device):
                success += 1
        
        logger.info(f"API update complete: {success}/{len(devices)} devices reported")


if __name__ == "__main__":
    main()
