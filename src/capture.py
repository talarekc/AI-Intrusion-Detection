#!/usr/bin/env python3
"""
capture.py - Live packet capture and attack classification for the IDS dashboard.

Sniffs traffic on an isolated VMnet adapter, classifies it into attack categories
using lightweight heuristics, and writes the result to live_events.json, which the
Streamlit dashboard reads to drive the live map and alert log.

Run from src/ in an Administrator terminal (sniffing requires elevated privileges).
"""

import json
import os
import time
import threading
from collections import defaultdict, deque

from scapy.all import AsyncSniffer, IP, TCP, conf

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# dashboard.py looks for live_events.json next to itself (src/dashboard/).
# capture.py lives in src/, so we point one level down into dashboard/.
OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "dashboard", "live_events.json"
)

# VMware host-only adapters appear as "VMware Virtual Ethernet Adapter for VMnetXX".
# Set this to match the VMnet you created. Change the number if you used a different one.
IFACE_MATCH = "VMnet10"

# Only analyze traffic destined for the target machine, so the target's own
# responses (e.g. RST packets during a scan) aren't misclassified as attacks.
TARGET_IP = "192.168.100.129"

WINDOW_SECONDS = 5      # rolling window analyzed each pass
ANALYZE_EVERY = 2.0     # seconds between classification passes

# Detection thresholds, per source IP, within the window
PORTSCAN_DISTINCT_PORTS = 15
BRUTEFORCE_PORT22_PACKETS = 20
WEBATTACK_PORT80_PACKETS = 25
DDOS_PACKETS = 300

# ---------------------------------------------------------------------------
# Packet store
# ---------------------------------------------------------------------------

lock = threading.Lock()
# bounded so an hping3 flood cannot exhaust memory; time pruning still applies
packets = deque(maxlen=100000)


def record(pkt):
    """Called for every sniffed packet. Keep it cheap."""
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return
    ip = pkt[IP]
    if ip.dst != TARGET_IP:
        return
    tcp = pkt[TCP]
    # Real application data only. A bare SYN packet (hping3 -S flood) has no app
    # data, but short Ethernet frames get a scapy Padding layer that would
    # otherwise be miscounted as payload and make a SYN flood look like HTTP.
    payload = tcp.payload
    if payload.__class__.__name__ == "Padding":
        has_payload = False
    else:
        has_payload = len(bytes(payload)) > 0
    with lock:
        packets.append(
            (time.time(), ip.src, ip.dst, int(tcp.dport), str(tcp.flags), has_payload)
        )


def prune(now):
    cutoff = now - WINDOW_SECONDS
    with lock:
        while packets and packets[0][0] < cutoff:
            packets.popleft()


# ---------------------------------------------------------------------------
# Classification (heuristic, drives the live map only)
# Cole's trained model still powers the static prediction_output.csv side.
# ---------------------------------------------------------------------------

def classify():
    now = time.time()
    prune(now)
    with lock:
        snapshot = list(packets)

    by_src = defaultdict(list)
    for ts, src, dst, dport, flags, payload in snapshot:
        by_src[src].append((dst, dport, flags, payload))

    events = []
    for src, recs in by_src.items():
        dst = recs[-1][0]
        distinct_ports = {r[1] for r in recs}
        total = len(recs)
        port22 = sum(1 for r in recs if r[1] == 22)
        port80_payload = sum(1 for r in recs if r[1] == 80 and r[3])
        # A SYN flood (hping3 -S --flood) is almost entirely bare SYN packets:
        # flags exactly "S". nikto makes real connections (PSH/ACK/FIN), so it
        # has very few SYN-only packets relative to its total. This flag pattern
        # is the reliable tell between a DDoS flood and a Web Attack.
        syn_only = sum(1 for r in recs if r[2] == "S")
        syn_fraction = syn_only / total if total else 0.0

        attack = "BENIGN"
        confidence = 0.50

        # Order by how distinctive each signal is:
        #  1. Port Scan   - many distinct ports.
        #  2. DDoS flood  - high volume that is mostly bare SYN packets
        #     (hping3 -S --flood), even when aimed at port 80. Checked before
        #     Web Attack so the flood isn't mislabeled.
        #  3. Web Attack  - many port-80 packets with real HTTP payload (nikto).
        #  4. DDoS        - high volume on a non-web port.
        #  5. Brute Force - many packets to port 22.
        if len(distinct_ports) >= PORTSCAN_DISTINCT_PORTS:
            attack = "Port Scan"
            confidence = min(0.99, 0.80 + len(distinct_ports) / 1000)
        elif total >= DDOS_PACKETS and syn_fraction >= 0.7:
            attack = "DDoS"
            confidence = min(0.99, 0.85 + total / 10000)
        elif port80_payload >= WEBATTACK_PORT80_PACKETS:
            attack = "Web Attack"
            confidence = min(0.99, 0.80 + port80_payload / 500)
        elif total >= DDOS_PACKETS:
            attack = "DDoS"
            confidence = min(0.99, 0.85 + total / 10000)
        elif port22 >= BRUTEFORCE_PORT22_PACKETS:
            attack = "Brute Force"
            confidence = min(0.99, 0.80 + port22 / 500)

        events.append(
            {
                "srcIp": src,
                "dstIp": dst,
                "attack": attack,
                "confidence": round(confidence, 3),
            }
        )

    return events


def write_events(events):
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    tmp = OUTPUT_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(events, f)
    os.replace(tmp, OUTPUT_PATH)  # atomic, so the dashboard never reads a half file


# ---------------------------------------------------------------------------
# Interface selection
# ---------------------------------------------------------------------------

def find_iface():
    for iface in conf.ifaces.values():
        blob = "{} {}".format(iface.name or "", iface.description or "")
        if IFACE_MATCH.lower() in blob.lower():
            return iface
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    iface = find_iface()
    if iface is None:
        print("[!] No interface matching '{}'.".format(IFACE_MATCH))
        print("    Available interfaces:")
        for i in conf.ifaces.values():
            print("      - {}  |  {}".format(i.name, i.description))
        print("    Edit IFACE_MATCH at the top of this script to match your adapter.")
        return

    print("[*] Sniffing on: {}".format(iface))
    print("[*] Writing events to: {}".format(OUTPUT_PATH))
    print("[*] Ctrl+C to stop.")

    sniffer = AsyncSniffer(iface=iface, prn=record, store=False)
    sniffer.start()

    try:
        while True:
            time.sleep(ANALYZE_EVERY)
            events = classify()
            write_events(events)
            for e in events:
                if e["attack"] != "BENIGN":
                    print("    {} -> {}  {} ({})".format(
                        e["srcIp"], e["dstIp"], e["attack"], e["confidence"]))
    except KeyboardInterrupt:
        print("\n[*] Stopping. Clearing live map.")
        sniffer.stop()
        write_events([])


if __name__ == "__main__":
    main()
