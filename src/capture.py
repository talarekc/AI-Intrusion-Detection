"""
capture.py — Live packet capture and real-time threat detection
Run this script DURING the attack simulation. It captures live network traffic,
extracts CICIDS2017-compatible flow features, runs them through the trained model,
and writes detections to live_events.json which the dashboard reads from.

Usage:
    Run as Administrator: python capture.py

Requirements:
    pip install scapy joblib pandas numpy
"""

import json
import os
import time
import math
import joblib
import numpy as np
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    print("Scapy not installed. Run: pip install scapy")
    exit(1)

# ---------------------------------------------------------------------------
# PATHS
# ---------------------------------------------------------------------------

MODEL_PATH   = r"C:\Users\brian\OneDrive - Sacred Heart University\AI-Intrusion-Detection\main model\models\random_forest_model.joblib"
ENCODER_PATH = r"C:\Users\brian\OneDrive - Sacred Heart University\AI-Intrusion-Detection\main model\models\label_encoder.joblib"
OUTPUT_PATH  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard", "live_events.json")

# Seconds of inactivity before a flow is considered finished
FLOW_TIMEOUT = 5.0

# ---------------------------------------------------------------------------
# LOAD MODEL
# ---------------------------------------------------------------------------

print("Loading model...")
model   = joblib.load(MODEL_PATH)
encoder = joblib.load(ENCODER_PATH)
print(f"Model loaded. Classes: {encoder.classes_}")
print(f"Writing detections to: {OUTPUT_PATH}")
print("-" * 50)

# ---------------------------------------------------------------------------
# FLOW CLASS
# ---------------------------------------------------------------------------

class Flow:
    def __init__(self, ts):
        self.start_time = ts
        self.last_time  = ts
        self.fwd_packets = []
        self.bwd_packets = []
        self.fwd_flags = defaultdict(int)
        self.bwd_flags = defaultdict(int)
        self.fwd_header_len = 0
        self.bwd_header_len = 0
        self.init_win_fwd = -1
        self.init_win_bwd = -1
        self.active_times = []
        self.idle_times   = []
        self._last_active  = ts
        self._active_start = ts
        self.fwd_bulk_bytes   = 0
        self.fwd_bulk_packets = 0
        self.bwd_bulk_bytes   = 0
        self.bwd_bulk_packets = 0

    def add_packet(self, ts, size, direction, flags, header_len, win_size):
        self.last_time = ts
        gap = ts - self._last_active
        if gap > 1.0:
            self.active_times.append(self._last_active - self._active_start)
            self.idle_times.append(gap)
            self._active_start = ts
        self._last_active = ts

        if direction == "fwd":
            self.fwd_packets.append((ts, size))
            self.fwd_header_len += header_len
            if self.init_win_fwd == -1 and win_size is not None:
                self.init_win_fwd = win_size
            for flag in flags:
                self.fwd_flags[flag] += 1
            self.fwd_bulk_bytes   += size
            self.fwd_bulk_packets += 1
        else:
            self.bwd_packets.append((ts, size))
            self.bwd_header_len += header_len
            if self.init_win_bwd == -1 and win_size is not None:
                self.init_win_bwd = win_size
            for flag in flags:
                self.bwd_flags[flag] += 1
            self.bwd_bulk_bytes   += size
            self.bwd_bulk_packets += 1

    def _iat(self, packets):
        if len(packets) < 2:
            return []
        times = [p[0] for p in packets]
        return [times[i+1] - times[i] for i in range(len(times)-1)]

    def _stats(self, values):
        if not values:
            return 0.0, 0.0, 0.0, 0.0
        mean = sum(values) / len(values)
        std  = math.sqrt(sum((v - mean)**2 for v in values) / len(values)) if len(values) > 1 else 0.0
        return mean, std, max(values), min(values)

    def extract_features(self, dst_port):
        duration = max(self.last_time - self.start_time, 1e-6)

        fwd_sizes = [p[1] for p in self.fwd_packets]
        bwd_sizes = [p[1] for p in self.bwd_packets]
        all_sizes = fwd_sizes + bwd_sizes

        fwd_mean, fwd_std, fwd_max, fwd_min = self._stats(fwd_sizes)
        bwd_mean, bwd_std, bwd_max, bwd_min = self._stats(bwd_sizes)
        all_mean, all_std, all_max, all_min = self._stats(all_sizes)

        all_pkts_sorted = sorted(self.fwd_packets + self.bwd_packets, key=lambda x: x[0])
        all_iats  = self._iat(all_pkts_sorted)
        fwd_iats  = self._iat(self.fwd_packets)
        bwd_iats  = self._iat(self.bwd_packets)

        iat_mean,  iat_std,  iat_max,  iat_min  = self._stats(all_iats)
        fiat_mean, fiat_std, fiat_max, fiat_min = self._stats(fwd_iats)
        biat_mean, biat_std, biat_max, biat_min = self._stats(bwd_iats)

        active_mean, active_std, active_max, active_min = self._stats(self.active_times)
        idle_mean,   idle_std,   idle_max,   idle_min   = self._stats(self.idle_times)

        total_fwd = len(self.fwd_packets)
        total_bwd = len(self.bwd_packets)
        total_fwd_bytes = sum(fwd_sizes)
        total_bwd_bytes = sum(bwd_sizes)

        flow_bytes_s   = (total_fwd_bytes + total_bwd_bytes) / duration
        flow_packets_s = (total_fwd + total_bwd) / duration
        fwd_packets_s  = total_fwd / duration
        bwd_packets_s  = total_bwd / duration
        down_up        = total_bwd / total_fwd if total_fwd > 0 else 0
        avg_pkt        = sum(all_sizes) / len(all_sizes) if all_sizes else 0

        fwd_avg_bytes_bulk   = self.fwd_bulk_bytes   / self.fwd_bulk_packets if self.fwd_bulk_packets > 0 else 0
        fwd_avg_packets_bulk = float(self.fwd_bulk_packets)
        fwd_avg_bulk_rate    = self.fwd_bulk_bytes   / duration
        bwd_avg_bytes_bulk   = self.bwd_bulk_bytes   / self.bwd_bulk_packets if self.bwd_bulk_packets > 0 else 0
        bwd_avg_packets_bulk = float(self.bwd_bulk_packets)
        bwd_avg_bulk_rate    = self.bwd_bulk_bytes   / duration

        return [
            dst_port,                       # Destination Port
            duration * 1e6,                 # Flow Duration (microseconds)
            total_fwd,                      # Total Fwd Packets
            total_bwd,                      # Total Backward Packets
            total_fwd_bytes,                # Total Length of Fwd Packets
            total_bwd_bytes,                # Total Length of Bwd Packets
            fwd_max,                        # Fwd Packet Length Max
            fwd_min,                        # Fwd Packet Length Min
            fwd_mean,                       # Fwd Packet Length Mean
            fwd_std,                        # Fwd Packet Length Std
            bwd_max,                        # Bwd Packet Length Max
            bwd_min,                        # Bwd Packet Length Min
            bwd_mean,                       # Bwd Packet Length Mean
            bwd_std,                        # Bwd Packet Length Std
            flow_bytes_s,                   # Flow Bytes/s
            flow_packets_s,                 # Flow Packets/s
            iat_mean,                       # Flow IAT Mean
            iat_std,                        # Flow IAT Std
            iat_max,                        # Flow IAT Max
            iat_min,                        # Flow IAT Min
            sum(fwd_iats),                  # Fwd IAT Total
            fiat_mean,                      # Fwd IAT Mean
            fiat_std,                       # Fwd IAT Std
            fiat_max,                       # Fwd IAT Max
            fiat_min,                       # Fwd IAT Min
            sum(bwd_iats),                  # Bwd IAT Total
            biat_mean,                      # Bwd IAT Mean
            biat_std,                       # Bwd IAT Std
            biat_max,                       # Bwd IAT Max
            biat_min,                       # Bwd IAT Min
            self.fwd_flags.get("P", 0),     # Fwd PSH Flags
            self.bwd_flags.get("P", 0),     # Bwd PSH Flags
            self.fwd_flags.get("U", 0),     # Fwd URG Flags
            self.bwd_flags.get("U", 0),     # Bwd URG Flags
            self.fwd_header_len,            # Fwd Header Length
            self.bwd_header_len,            # Bwd Header Length
            fwd_packets_s,                  # Fwd Packets/s
            bwd_packets_s,                  # Bwd Packets/s
            all_min,                        # Min Packet Length
            all_max,                        # Max Packet Length
            all_mean,                       # Packet Length Mean
            all_std,                        # Packet Length Std
            all_std ** 2,                   # Packet Length Variance
            self.fwd_flags.get("F", 0) + self.bwd_flags.get("F", 0),
            self.fwd_flags.get("S", 0) + self.bwd_flags.get("S", 0),
            self.fwd_flags.get("R", 0) + self.bwd_flags.get("R", 0),
            self.fwd_flags.get("P", 0) + self.bwd_flags.get("P", 0),
            self.fwd_flags.get("A", 0) + self.bwd_flags.get("A", 0),
            self.fwd_flags.get("U", 0) + self.bwd_flags.get("U", 0),
            self.fwd_flags.get("C", 0) + self.bwd_flags.get("C", 0),
            self.fwd_flags.get("E", 0) + self.bwd_flags.get("E", 0),
            down_up,                        # Down/Up Ratio
            avg_pkt,                        # Average Packet Size
            fwd_mean,                       # Avg Fwd Segment Size
            bwd_mean,                       # Avg Bwd Segment Size
            self.fwd_header_len,            # Fwd Header Length.1
            fwd_avg_bytes_bulk,             # Fwd Avg Bytes/Bulk
            fwd_avg_packets_bulk,           # Fwd Avg Packets/Bulk
            fwd_avg_bulk_rate,              # Fwd Avg Bulk Rate
            bwd_avg_bytes_bulk,             # Bwd Avg Bytes/Bulk
            bwd_avg_packets_bulk,           # Bwd Avg Packets/Bulk
            bwd_avg_bulk_rate,              # Bwd Avg Bulk Rate
            float(total_fwd),               # Subflow Fwd Packets
            float(total_fwd_bytes),         # Subflow Fwd Bytes
            float(total_bwd),               # Subflow Bwd Packets
            float(total_bwd_bytes),         # Subflow Bwd Bytes
            float(self.init_win_fwd if self.init_win_fwd >= 0 else 0),
            float(self.init_win_bwd if self.init_win_bwd >= 0 else 0),
            float(total_fwd),               # act_data_pkt_fwd
            20.0,                           # min_seg_size_forward
            active_mean,                    # Active Mean
            active_std,                     # Active Std
            active_max,                     # Active Max
            active_min,                     # Active Min
            idle_mean,                      # Idle Mean
            idle_std,                       # Idle Std
            idle_max,                       # Idle Max
            idle_min,                       # Idle Min
        ]


# ---------------------------------------------------------------------------
# FLOW TABLE
# ---------------------------------------------------------------------------

flows = {}

def get_flow_key(packet):
    if IP not in packet:
        return None
    proto = 6 if TCP in packet else (17 if UDP in packet else 0)
    src   = packet[IP].src
    dst   = packet[IP].dst
    sport = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)
    dport = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)
    if (src, sport) < (dst, dport):
        return (src, dst, sport, dport, proto)
    else:
        return (dst, src, dport, sport, proto)

def get_direction(packet, key):
    if IP not in packet:
        return "fwd"
    src   = packet[IP].src
    sport = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)
    return "fwd" if (src, sport) == (key[0], key[2]) else "bwd"

def get_flags(packet):
    flags = []
    if TCP in packet:
        f = packet[TCP].flags
        if f & 0x01: flags.append("F")
        if f & 0x02: flags.append("S")
        if f & 0x04: flags.append("R")
        if f & 0x08: flags.append("P")
        if f & 0x10: flags.append("A")
        if f & 0x20: flags.append("U")
        if f & 0x40: flags.append("E")
        if f & 0x80: flags.append("C")
    return flags


# ---------------------------------------------------------------------------
# EVENT WRITER
# ---------------------------------------------------------------------------

def write_event(event: dict):
    existing = []
    if os.path.exists(OUTPUT_PATH):
        try:
            with open(OUTPUT_PATH, "r") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, IOError):
            existing = []
    existing.append(event)
    if len(existing) > 500:
        existing = existing[-500:]
    with open(OUTPUT_PATH, "w") as f:
        json.dump(existing, f)


# ---------------------------------------------------------------------------
# CLASSIFY A FINISHED FLOW
# ---------------------------------------------------------------------------

def classify_flow(key, flow):
    dst_port = key[3]
    features = flow.extract_features(dst_port)

    try:
        arr = np.array(features, dtype=float).reshape(1, -1)
        arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
        prediction = model.predict(arr)
        label      = encoder.inverse_transform(prediction)[0]
        confidence = float(model.predict_proba(arr).max())
    except Exception as e:
        print(f"Prediction error: {e}")
        return

    src_ip   = key[0]
    dst_ip   = key[1]
    src_port = key[2]

    tag = "[THREAT]" if label != "BENIGN" else "[benign]"
    print(f"{tag} {label} ({confidence:.1%}) | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

    if label != "BENIGN":
        write_event({
            "srcIp":      src_ip,
            "dstIp":      dst_ip,
            "srcPort":    src_port,
            "dstPort":    dst_port,
            "attack":     label,
            "confidence": round(confidence, 3),
            "timestamp":  time.strftime("%Y-%m-%d %H:%M:%S"),
        })


# ---------------------------------------------------------------------------
# PACKET HANDLER
# ---------------------------------------------------------------------------

packet_count = 0
last_timeout_check = time.time()

def on_packet(packet):
    global packet_count, last_timeout_check
    packet_count += 1

    if IP not in packet:
        return

    key = get_flow_key(packet)
    if key is None:
        return

    ts      = time.time()
    size    = len(packet)
    flags   = get_flags(packet)
    hdr_len = (packet[TCP].dataofs * 4) if TCP in packet else (8 if UDP in packet else 20)
    win     = packet[TCP].window if TCP in packet else None

    if key not in flows:
        flows[key] = Flow(ts)

    flow = flows[key]
    direction = get_direction(packet, key)
    flow.add_packet(ts, size, direction, flags, hdr_len, win)

    # Finish flow on FIN or RST
    if TCP in packet and (packet[TCP].flags & 0x01 or packet[TCP].flags & 0x04):
        classify_flow(key, flow)
        del flows[key]
        return

    # Flush timed-out flows every 2 seconds
    if ts - last_timeout_check > 2.0:
        last_timeout_check = ts
        timed_out = [k for k, f in flows.items() if ts - f.last_time > FLOW_TIMEOUT]
        for k in timed_out:
            classify_flow(k, flows[k])
            del flows[k]

    if packet_count % 500 == 0:
        print(f"[INFO] {packet_count} packets processed | {len(flows)} active flows")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    with open(OUTPUT_PATH, "w") as f:
        json.dump([], f)
    print("Cleared previous events.")
    print("Listening for live traffic... press Ctrl+C to stop.\n")

    try:
        sniff(prn=on_packet, store=False)
    except KeyboardInterrupt:
        print(f"\nStopped. {packet_count} packets processed.")
        print(f"Flushing {len(flows)} remaining flows...")
        for key, flow in list(flows.items()):
            classify_flow(key, flow)
        print("Done.")
    except PermissionError:
        print("\nPermission denied. Run this script as Administrator.")
