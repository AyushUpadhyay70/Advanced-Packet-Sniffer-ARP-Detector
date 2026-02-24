# Advanced-Packet-Sniffer-ARP-Detector
"Real-time ARP spoofing detection tool built using Scapy"

# Advanced Packet Sniffer + ARP Spoofing Detector

## Overview
This project is a Python-based real-time packet sniffer and ARP spoofing detection tool built using Scapy.

It monitors network traffic and detects suspicious IP-to-MAC mapping changes that may indicate ARP spoofing or Man-in-the-Middle attacks.

## Features
- Real-time packet capture
- ARP traffic monitoring
- IP-MAC mapping verification
- ARP spoofing detection alerts
- Logging of suspicious activity

## Requirements
- Python 3.x
- Scapy
- Root/Administrator privileges

Install dependencies:

pip install -r requirements.txt

## Usage

Run full packet sniffer:

sudo python main.py

Run ARP spoofing detector only:

sudo python main.py --arp-only

Specify interface:

sudo python main.py --interface wlan0 --arp-only

## How It Works

The tool:
1. Sniffs ARP reply packets
2. Stores IP-to-MAC mappings
3. Detects changes in mapping
4. Alerts if MAC address changes unexpectedly

## Educational Purpose

This tool demonstrates:
- Packet structures
- ARP protocol behavior
- Basic intrusion detection logic

## Ethical Notice

Run this tool only on networks you own or have explicit permission to monitor.
Unauthorized packet sniffing may violate laws or policies.
