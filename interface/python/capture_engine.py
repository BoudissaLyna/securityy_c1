#!/usr/bin/env python3
"""
============================================================
 DNS TUNNEL SENTINEL — Real-Time Capture Engine
 Sniffs DNS packets via Scapy, analyzes for tunneling,
 and streams results over WebSocket to the Electron frontend.
============================================================
Requires: pip install scapy websockets joblib scikit-learn xgboost
Must be run with administrator/root privileges for packet capture.
"""

import asyncio
import json
import math
import time
import threading
import sys
import os
from collections import Counter, deque
from datetime import datetime

# ── Load ML model ──
try:
    import joblib
    import numpy as np
    import pandas as pd
    _MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "best_model.joblib")
    _MODEL_PATH = os.path.abspath(_MODEL_PATH)
    ML_MODEL = joblib.load(_MODEL_PATH)
    ML_FEATURE_COLS = [
        "duration", "total_bytes", "receiving_bytes",
        "packets_rate", "packets_len_rate",
        "min_packets_len", "max_packets_len", "mean_packets_len",
        "standard_deviation_packets_len",
        "dns_domain_name_length", "dns_subdomain_name_length",
        "numerical_percentage", "character_entropy",
        "max_continuous_numeric_len", "max_continuous_alphabet_len",
        "max_continuous_consonants_len", "max_continuous_same_alphabet_len",
        "vowels_consonant_ratio", "conv_freq_vowels_consonants",
        "distinct_ttl_values",
        "ttl_values_min", "ttl_values_max", "ttl_values_mean",
        "ttl_values_mode", "ttl_values_median",
        "distinct_A_records",
        "rr_type_count", "rr_type_has_A", "rr_type_has_CNAME",
        "rr_type_has_TXT", "rr_type_unique", "rr_class_count",
        "num_dots", "subdomain_depth",
        "digit_ratio", "letter_ratio", "special_char_count", "unique_chars",
    ]
    ML_AVAILABLE = True
    print(f"[ML] Model loaded from {_MODEL_PATH}", file=sys.stderr)
except Exception as _e:
    ML_MODEL = None
    ML_FEATURE_COLS = []
    ML_AVAILABLE = False
    print(f"[ML] Model NOT loaded: {_e}", file=sys.stderr)

try:
    from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    print("[CAPTURE ENGINE] Scapy not installed. Install with: pip install scapy", file=sys.stderr)
    SCAPY_AVAILABLE = False

try:
    import websockets
    from websockets.asyncio.server import serve
except ImportError:
    print("[CAPTURE ENGINE] websockets not installed. Install with: pip install websockets", file=sys.stderr)
    sys.exit(1)

# ── Configuration ──
WS_HOST = "127.0.0.1"
WS_PORT = 8765
SNIFF_FILTER = "udp port 53"

# ── Known malicious / C2 domains ──
KNOWN_C2_DOMAINS = {
    "evil-c2.xyz", "malware-beacon.ru", "exfil-tunnel.io",
    "apt-staging.cn", "backdoor-ctrl.net", "dns-covert.xyz",
    "c2-server.biz", "botnet-dns.tk", "payload-drop.ml",
}

SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".cf", ".ga", ".biz", ".top", ".pw", ".cc"}

# ── Beaconing detection state ──
query_history = deque(maxlen=5000)
domain_freq = Counter()

# ── Packet queue (thread-safe) ──
packet_queue = deque(maxlen=1000)
packet_id_counter = 0
connected_clients = set()

# ── Dynamic Blocklist (Active Defense) ──
blocked_ips = set()
blocked_domains = set()


def calc_entropy(s):
    if not s: return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def is_base64_like(s):
    if len(s) < 8: return False
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    ratio = sum(1 for c in s if c in b64_chars) / len(s)
    return ratio > 0.85 and len(s) > 12


def detect_beaconing(domain, window_seconds=60, threshold=10):
    now = time.time()
    base = ".".join(domain.split(".")[-2:])
    query_history.append((now, base))
    count = sum(1 for ts, d in query_history if d == base and now - ts < window_seconds)
    return count >= threshold


def analyze_dns_packet(pkt):
    global packet_id_counter
    if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR): return None
    dns_layer = pkt[DNS]
    if dns_layer.qr == 1: return None # Ignore responses (like those from 10.73.26.162)
    query = pkt[DNSQR]
    try:
        domain = query.qname.decode("utf-8", errors="ignore").rstrip(".")
    except: return None
    if not domain: return None

    qtype_map = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
    query_type = qtype_map.get(query.qtype, str(query.qtype))
    src_ip = pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0"
    byte_size = len(pkt)

    parts = domain.split(".")
    # Always analyze the first label of the domain (e.g., "google" in "google.com")
    subdomain = parts[0] if parts else ""
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    entropy = round(calc_entropy(subdomain), 2) if subdomain else 0.0

    status = "CLEAN"
    detection_rule = None

    # 1. Check Dynamic Blocklists (Active Defense)
    if src_ip in blocked_ips:
        status = "BLOCKED"; detection_rule = "IP MANUALLY BLOCKED (Sentinel)"
    elif base_domain.lower() in blocked_domains:
        status = "BLOCKED"; detection_rule = "DOMAIN MANUALLY BLOCKED (Sentinel)"
    # 2. Check Static Blocklists
    elif base_domain.lower() in KNOWN_C2_DOMAINS:
        status = "BLOCKED"; detection_rule = "KNOWN C2 DOMAIN"
    elif entropy > 3.8 and len(subdomain) > 20:
        status = "BLOCKED"; detection_rule = "HIGH ENTROPY SUBDOMAIN"
    elif is_base64_like(subdomain):
        status = "BLOCKED"; detection_rule = "PAYLOAD ENCODING DETECTED"
    elif query_type in ("TXT", "NULL") and len(domain) > 50:
        status = "BLOCKED"; detection_rule = "COVERT CHANNEL DETECTED"
    elif detect_beaconing(domain):
        status = "SUSPICIOUS"; detection_rule = "BEACONING PATTERN"
    elif entropy > 3.2 and len(subdomain) > 10:
        status = "SUSPICIOUS"; detection_rule = "ENCODED SUBDOMAIN"
    elif len(domain) > 70:
        status = "SUSPICIOUS"; detection_rule = "ABNORMAL QUERY LENGTH"
    elif query_type == "NULL":
        status = "SUSPICIOUS"; detection_rule = "NULL QUERY ANOMALY"
    elif any(domain.lower().endswith(tld) for tld in SUSPICIOUS_TLDS):
        if entropy > 2.5 or len(subdomain) > 15:
            status = "SUSPICIOUS"; detection_rule = "SUSPICIOUS TLD + PATTERN"

    packet_id_counter += 1
    now = datetime.now()
    timestamp = now.strftime("%H:%M:%S") + f".{now.microsecond // 1000:03d}"

    return {
        "id": packet_id_counter,
        "timestamp": timestamp,
        "sourceIp": src_ip,
        "domain": domain,
        "queryType": query_type,
        "byteSize": byte_size,
        "status": status,
        "entropy": entropy,
        "detectionRule": detection_rule,
    }


def sniff_dns():
    print(f"[CAPTURE ENGINE] Starting DNS capture on filter: {SNIFF_FILTER}")
    try:
        sniff(filter=SNIFF_FILTER, prn=lambda pkt: _on_packet(pkt), store=False)
    except PermissionError:
        print("[CAPTURE ENGINE] ERROR: Requires administrator/root privileges!", file=sys.stderr)
    except Exception as e:
        print(f"[CAPTURE ENGINE] Sniff error: {e}", file=sys.stderr)


def _on_packet(pkt):
    result = analyze_dns_packet(pkt)
    if result:
        print(f"[CAPTURE] {result['status']} | {result['domain']} ({result['entropy']})")
        packet_queue.append(result)


async def ws_handler(websocket):
    connected_clients.add(websocket)
    print(f"[WS] Client connected ({len(connected_clients)} total)")
    await websocket.send(json.dumps({"type": "status", "message": "CAPTURE ENGINE CONNECTED", "captureActive": SCAPY_AVAILABLE}))
    try:
        async for message in websocket:
            try:
                cmd = json.loads(message)
                if cmd.get("action") == "ping": 
                    await websocket.send(json.dumps({"type": "pong"}))
                elif cmd.get("action") == "block_ip":
                    ip = cmd.get("ip")
                    if ip:
                        blocked_ips.add(ip)
                        print(f"[DEFENSE] Added {ip} to local blocklist")
                elif cmd.get("action") == "block_domain":
                    domain = cmd.get("domain")
                    if domain:
                        blocked_domains.add(domain)
                        print(f"[DEFENSE] Added {domain} to local blocklist")
            except: pass
    except websockets.exceptions.ConnectionClosed: pass
    finally:
        connected_clients.discard(websocket)
        print(f"[WS] Client disconnected ({len(connected_clients)} total)")


async def broadcast_packets():
    while True:
        if packet_queue and connected_clients:
            batch = []
            while packet_queue: batch.append(packet_queue.popleft())
            msg = json.dumps({"type": "packets", "data": batch})
            disconnected = set()
            for ws in connected_clients:
                try: await ws.send(msg)
                except websockets.exceptions.ConnectionClosed: disconnected.add(ws)
            connected_clients.difference_update(disconnected)
        await asyncio.sleep(0.1)


def _ml_infer(features: dict):
    """
    Run the XGBoost pipeline on a feature dict from extractor.py.
    Returns (status, detection_rule, confidence) tuple.
    """
    if not ML_AVAILABLE:
        # Fallback: entropy threshold
        ent = features.get("character_entropy", 0)
        if ent > 3.5:
            return "SUSPICIOUS", "ENTROPY THRESHOLD (no model)", 0.0
        return "CLEAN", None, 0.0

    try:
        row = {col: features.get(col, 0) for col in ML_FEATURE_COLS}
        X = pd.DataFrame([row], columns=ML_FEATURE_COLS)
        pred = int(ML_MODEL.predict(X)[0])
        proba = ML_MODEL.predict_proba(X)[0]
        confidence = round(float(proba[pred]) * 100, 1)

        if pred == 1:
            return "BLOCKED", f"ML: DNS TUNNEL ({confidence}% conf.)", confidence
        else:
            return "CLEAN", None, confidence
    except Exception as e:
        print(f"[ML] Inference error: {e}", file=sys.stderr)
        return "SUSPICIOUS", "ML ERROR — FALLBACK", 0.0


async def bridge_handler(reader, writer):
    try:
        data = await reader.read(65536)
        if not data:
            return
        request_text = data.decode('utf-8', errors='ignore')
        if "POST" in request_text and "{" in request_text:
            json_part = request_text[request_text.find("{"):]
            try:
                ext = json.loads(json_part)
                status, rule, confidence = _ml_infer(ext)
                mapped_pkt = {
                    "id":            int(time.time() * 1000) % 1000000,
                    "timestamp":     datetime.now().strftime("%H:%M:%S"),
                    "sourceIp":      ext.get("_src_ip", ext.get("src_ip", "EXT")),
                    "domain":        ext.get("_domain", ext.get("dns_domain_name", "unknown")),
                    "queryType":     "ML",
                    "byteSize":      int(ext.get("total_bytes", 0)),
                    "status":        status,
                    "entropy":       round(ext.get("character_entropy", 0), 3),
                    "detectionRule": rule,
                    "confidence":    confidence,
                    "features":      ext # Pass through all features for UI inspection
                }
                print(f"[ML-BRIDGE] {status} | {mapped_pkt['domain']} | "
                      f"entropy={mapped_pkt['entropy']} conf={confidence}%")
                packet_queue.append(mapped_pkt)
            except Exception as e:
                print(f"[BRIDGE] Parse error: {e}", file=sys.stderr)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def start_bridge():
    server = await asyncio.start_server(bridge_handler, '127.0.0.1', 8000)
    print(f"[BRIDGE] Listener active on http://127.0.0.1:8000")
    async with server: await server.serve_forever()


async def main():
    print(f"[CAPTURE ENGINE] DNS Tunnel Sentinel v2.4.1")
    if SCAPY_AVAILABLE:
        threading.Thread(target=sniff_dns, daemon=True).start()
        print("[CAPTURE ENGINE] Scapy DNS sniffer started")
    async with serve(ws_handler, WS_HOST, WS_PORT):
        print(f"[WS] Server listening on ws://{WS_HOST}:{WS_PORT}")
        await asyncio.gather(broadcast_packets(), start_bridge())


if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: print("\n[SHUTDOWN]")
