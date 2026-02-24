import argparse
from scapy.all import sniff, ARP
from datetime import datetime

# Store legitimate IP-MAC mappings
arp_table = {}


# -----------------------------
# Log Suspicious Activity
# -----------------------------
def log_alert(message):
    with open("arp_alerts.log", "a") as log:
        log.write(f"{datetime.now()} - {message}\n")


# -----------------------------
# ARP Spoof Detection Logic
# -----------------------------
def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in arp_table:
            if arp_table[ip] != mac:
                alert = f"[ALERT] Possible ARP Spoofing Detected! IP: {ip} | Old MAC: {arp_table[ip]} | New MAC: {mac}"
                print(alert)
                log_alert(alert)
        else:
            arp_table[ip] = mac

        print(f"[INFO] ARP Reply | IP: {ip} | MAC: {mac}")


# -----------------------------
# Packet Summary Display
# -----------------------------
def packet_summary(packet):
    print(packet.summary())


# -----------------------------
# Main Function
# -----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Advanced Packet Sniffer + ARP Spoofing Detector"
    )

    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface to sniff on (e.g., eth0, wlan0)"
    )

    parser.add_argument(
        "--arp-only",
        action="store_true",
        help="Monitor only ARP traffic"
    )

    args = parser.parse_args()

    print("\n=== Advanced Packet Sniffer + ARP Detector Started ===\n")
    print("Press CTRL+C to stop.\n")

    try:
        if args.arp_only:
            sniff(filter="arp", prn=detect_arp_spoof, iface=args.interface, store=False)
        else:
            sniff(prn=packet_summary, iface=args.interface, store=False)

    except KeyboardInterrupt:
        print("\nSniffing stopped.")


if __name__ == "__main__":
    main()
