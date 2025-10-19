#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp, conf
import ipaddress
import requests
import os
import sys
import time

API_URL = os.environ.get("NETVISION_API", "http://127.0.0.1:5000/api/device")

def arp_scan(network_cidr, timeout=3, retry=2):
    net = ipaddress.ip_network(network_cidr, strict=False)
    target = str(net)
    conf.verb = 0
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target)
    ans, _ = srp(pkt, timeout=timeout, retry=retry)
    devices = []
    for snd, rcv in ans:
        ip = rcv.psrc
        mac = rcv.hwsrc
        devices.append((ip, mac))
    return devices

def post_device(ip, mac, hostname=None, info=None):
    payload = {"ip": ip, "mac": mac}
    if hostname:
        payload["hostname"] = hostname
    if info:
        payload["info"] = info
    try:
        requests.post(API_URL, json=payload, timeout=5)
    except Exception as e:
        # swallow network errors; print minimal debug
        print(f"API error: {e}")

def main():
    if len(sys.argv) >= 2:
        network = sys.argv[1]
    else:
        network = input("Enter network CIDR (e.g. 192.168.1.0/24): ").strip()
    try:
        # validate
        ipaddress.ip_network(network, strict=False)
    except Exception as e:
        print(f"Invalid network CIDR: {e}")
        sys.exit(1)

    print(f"Scanning {network} ... (this requires root privileges)")
    found = arp_scan(network)
    if not found:
        print("No hosts found or scan timed out.")
        sys.exit(0)

    for ip, mac in found:
        print(f"{ip} - {mac}")
        post_device(ip, mac, info={"source": "arp_scan", "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ")})

if __name__ == "__main__":
    main()
PY
