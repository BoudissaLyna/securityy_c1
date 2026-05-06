#!/usr/bin/env python3
"""
============================================================
 DNS TUNNEL SENTINEL — Active Inline Gatekeeper
 Intercepts UDP port 53 traffic using PyDivert, extracts
 38 flow-level features via Scapy, and queries the ML backend.
 If prediction is 'Tunnel' / 'malicious' / '1', drops the packet.
 Otherwise, re-injects the packet back to the network.

 REQUIRES:  pip install httpx pydivert scapy
 NOTE: Must be run as Administrator on Windows.
============================================================
"""
import sys
import math
import json
import httpx
import time
from collections import defaultdict, Counter
from statistics import mean, median, mode

# Third-party imports
try:
    import pydivert
    from scapy.all import IP, IPv6, UDP, DNS
except ImportError as e:
    print(f"Error importing dependencies: {e}")
    print("Please ensure you have installed: pip install httpx pydivert scapy")
    sys.exit(1)

BACKEND_URL = "http://127.0.0.1:8000/analyze"

# =========================
# FLOW STORAGE
# =========================
flows = defaultdict(lambda: {
    "timestamps": [],
    "packet_sizes": [],        # outgoing (query) sizes
    "recv_sizes": [],          # incoming (response) sizes
    "ttls": [],
    "a_records": set(),
    "rr_types": [],            # list of dns.resp.type values
    "rr_classes": [],          # list of unique rr_types
    "src_ip": "",
    "dst_ip": "",
    "domain": "",
    "verdict": None            # Cache the verdict so we don't query repeatedly
})


# =========================
# SAFE HELPERS
# =========================

def safe_int(x, default=0):
    try:
        return int(x)
    except:
        return default

def safe_float(x, default=0.0):
    try:
        return float(x)
    except:
        return default

def entropy(s):
    if not s:
        return 0.0
    freq = Counter(s)
    l = len(s)
    return -sum((c / l) * math.log2(c / l) for c in freq.values())

def max_consecutive(s, condition):
    best = cur = 0
    for ch in s:
        if condition(ch):
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best

def max_same_char(s):
    if not s:
        return 0
    best = cur = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            cur += 1
            best = max(best, cur)
        else:
            cur = 1
    return best

def vowel_consonant_ratio(s):
    vowels = set("aeiouAEIOU")
    v = sum(1 for c in s if c in vowels)
    c = sum(1 for c in s if c.isalpha() and c not in vowels)
    return v / max(c, 1)

def is_consonant(ch):
    return ch.isalpha() and ch.lower() not in "aeiou"

def conv_freq_vowels_consonants(s):
    if len(s) < 2:
        return 0
    vowels = set("aeiouAEIOU")
    transitions = 0
    for i in range(1, len(s)):
        a_is_vowel = s[i-1] in vowels and s[i-1].isalpha()
        b_is_vowel = s[i] in vowels and s[i].isalpha()
        a_is_alpha = s[i-1].isalpha()
        b_is_alpha = s[i].isalpha()
        if a_is_alpha and b_is_alpha and (a_is_vowel != b_is_vowel):
            transitions += 1
    return transitions

def safe_mode(vals):
    if not vals:
        return -1
    try:
        return mode(vals)
    except:
        return Counter(vals).most_common(1)[0][0]


# =========================
# FLOW UPDATE
# =========================

def update_flow(scapy_pkt, packet_len):
    if IP in scapy_pkt:
        src_ip = scapy_pkt[IP].src
        dst_ip = scapy_pkt[IP].dst
    elif IPv6 in scapy_pkt:
        src_ip = scapy_pkt[IPv6].src
        dst_ip = scapy_pkt[IPv6].dst
    else:
        return None

    if not scapy_pkt.haslayer(DNS):
        return None

    dns_layer = scapy_pkt[DNS]
    
    # Scapy QR: 0 = query, 1 = response
    is_response = (dns_layer.qr == 1)

    # Use canonical flow ID to group bidirectional communication
    canonical_id = f"{min(src_ip, dst_ip)}={max(src_ip, dst_ip)}"
    now = time.time()

    f = flows[canonical_id]
    f["timestamps"].append(now)
    f["src_ip"] = src_ip
    f["dst_ip"] = dst_ip
    
    # Extract Domain
    domain = ""
    if dns_layer.qdcount > 0 and dns_layer.qd is not None:
        try:
            domain = dns_layer.qd[0].qname.decode('utf-8', errors='ignore')
        except:
            domain = str(dns_layer.qd[0].qname)
            
    if domain:
        f["domain"] = domain
        
    if is_response:
        f["recv_sizes"].append(packet_len)
    else:
        f["packet_sizes"].append(packet_len)

    if is_response and dns_layer.ancount > 0 and dns_layer.an is not None:
        for i in range(dns_layer.ancount):
            ans = dns_layer.an[i]
            if hasattr(ans, 'ttl'):
                f["ttls"].append(ans.ttl)
            if hasattr(ans, 'type'):
                rr_type = ans.type
                f["rr_types"].append(rr_type)
                if rr_type == 1: # A record
                    if hasattr(ans, 'rdata'):
                        rdata = ans.rdata
                        if isinstance(rdata, bytes):
                            f["a_records"].add(rdata.decode('utf-8', errors='ignore'))
                        else:
                            f["a_records"].add(str(rdata))

    f["rr_classes"] = list(set(f["rr_types"]))
    return canonical_id


# =========================
# FEATURE BUILDER — 38 features matching model
# =========================

def build_features(flow_id):
    f = flows[flow_id]

    all_sizes = f["packet_sizes"] + f["recv_sizes"]
    if len(f["timestamps"]) < 2 or not all_sizes:
        return None

    t = f["timestamps"]
    sizes = f["packet_sizes"] if f["packet_sizes"] else all_sizes
    recv  = f["recv_sizes"]
    ttls  = f["ttls"]
    domain = f["domain"] or ""

    duration    = max(t) - min(t)
    total_bytes = sum(sizes)
    recv_bytes  = sum(recv) if recv else 0

    mean_size = mean(sizes) if sizes else 0.0
    var       = mean([(x - mean_size) ** 2 for x in sizes]) if sizes else 0.0
    std       = math.sqrt(var)

    # Domain decomposition
    labels = domain.rstrip(".").split(".") if domain else []
    sub = ".".join(labels[:-2]) if len(labels) > 2 else ""

    ent      = entropy(sub)
    num_pct  = sum(c.isdigit() for c in sub) / max(len(sub), 1)
    let_pct  = sum(c.isalpha() for c in sub) / max(len(sub), 1)
    num_dots = domain.count(".")
    depth    = len(labels) - 2 if len(labels) > 2 else 0  # subdomain depth

    spec_chars = sum(1 for c in sub if not c.isalnum() and c != ".")
    uniq_chars = len(set(sub)) if sub else 0

    # RR type flags
    rr_types_set = set(f["rr_types"])
    rr_type_has_A     = int(1 in rr_types_set)
    rr_type_has_CNAME = int(5 in rr_types_set)
    rr_type_has_TXT   = int(16 in rr_types_set)
    rr_type_unique    = len(rr_types_set)
    rr_type_count     = len(f["rr_types"])
    rr_class_count    = len(f["rr_classes"])

    return {
        # ── Flow stats ──
        "duration":                          duration,
        "total_bytes":                       total_bytes,
        "receiving_bytes":                   recv_bytes,
        "packets_rate":                      len(sizes) / max(duration, 1e-6),
        "packets_len_rate":                  total_bytes / max(duration, 1e-6),
        "min_packets_len":                   min(sizes),
        "max_packets_len":                   max(sizes),
        "mean_packets_len":                  mean_size,
        "standard_deviation_packets_len":    std,
        # ── Domain length features ──
        "dns_domain_name_length":            len(domain),
        "dns_subdomain_name_length":         len(sub),
        # ── Subdomain character features ──
        "numerical_percentage":              num_pct,
        "character_entropy":                 ent,
        "max_continuous_numeric_len":        max_consecutive(sub, str.isdigit),
        "max_continuous_alphabet_len":       max_consecutive(sub, str.isalpha),
        "max_continuous_consonants_len":     max_consecutive(sub, is_consonant),
        "max_continuous_same_alphabet_len":  max_same_char(sub),
        "vowels_consonant_ratio":            vowel_consonant_ratio(sub),
        "conv_freq_vowels_consonants":       conv_freq_vowels_consonants(sub),
        # ── TTL features ──
        "distinct_ttl_values":               len(set(ttls)) if ttls else 0,
        "ttl_values_min":                    min(ttls) if ttls else -1,
        "ttl_values_max":                    max(ttls) if ttls else -1,
        "ttl_values_mean":                   mean(ttls) if ttls else -1,
        "ttl_values_mode":                   safe_mode(ttls),
        "ttl_values_median":                 median(ttls) if ttls else -1,
        # ── DNS record features ──
        "distinct_A_records":                len(f["a_records"]),
        "rr_type_count":                     rr_type_count,
        "rr_type_has_A":                     rr_type_has_A,
        "rr_type_has_CNAME":                 rr_type_has_CNAME,
        "rr_type_has_TXT":                   rr_type_has_TXT,
        "rr_type_unique":                    rr_type_unique,
        "rr_class_count":                    rr_class_count,
        # ── Domain structure features ──
        "num_dots":                          num_dots,
        "subdomain_depth":                   depth,
        "digit_ratio":                       num_pct,
        "letter_ratio":                      let_pct,
        "special_char_count":               spec_chars,
        "unique_chars":                      uniq_chars,
        # ── Metadata (not fed to model) ──
        "_flow_id":  flow_id,
        "_src_ip":   f["src_ip"],
        "_dst_ip":   f["dst_ip"],
        "_domain":   domain,
    }


# =========================
# GATEKEEPER LOGIC
# =========================

def check_verdict(features):
    """
    Query the ML endpoint. Return True if the verdict is malicious ('Tunnel').
    """
    try:
        resp = httpx.post(BACKEND_URL, json=features, timeout=1.0)
        if resp.status_code == 200:
            result = resp.json()
            
            # Accommodate various possible response keys indicating malice
            for key in ["prediction", "verdict", "result"]:
                val = result.get(key)
                if val in [1, '1', 'malicious', 'Tunnel']:
                    return True
    except Exception:
        # Fail-safe: if the backend is unreachable or times out, allow traffic
        pass
    return False

def main():
    print("=====================================================")
    print(" DNS Tunnel Sentinel — Active Gatekeeper")
    print(" Intercepting UDP Port 53 traffic. Press Ctrl+C to stop.")
    print("=====================================================")

    try:
        with pydivert.WinDivert("udp.DstPort == 53 or udp.SrcPort == 53") as w:
            for packet in w:
                drop_packet = False
                try:
                    raw_bytes = packet.raw
                    scapy_pkt = IP(raw_bytes) if packet.is_ipv4 else IPv6(raw_bytes)
                    
                    # Approximate full Ethernet frame length for model compatibility
                    # tshark frame.len includes Ethernet header (~14 bytes)
                    packet_len = len(raw_bytes) + 14 
                    
                    flow_id = update_flow(scapy_pkt, packet_len)
                    
                    if flow_id:
                        f = flows[flow_id]
                        
                        # Once marked as a Tunnel, actively drop subsequent packets in flow
                        if f.get("verdict") == "Tunnel":
                            drop_packet = True
                        else:
                            features = build_features(flow_id)
                            if features:
                                is_malicious = check_verdict(features)
                                if is_malicious:
                                    f["verdict"] = "Tunnel"
                                    drop_packet = True
                                    print(f"[!] DROPPING TUNNEL TRAFFIC -> Flow: {flow_id} | Domain: {f['domain']}")
                except Exception as e:
                    # Fail-safe: ignore parsing errors to prevent dropping innocent traffic
                    pass
                
                # Active re-injection if the packet was not classified as a Tunnel
                if not drop_packet:
                    w.send(packet)
                    
    except PermissionError:
        print("\n[ERROR] PyDivert requires administrative privileges.")
        print("Please run this script as an Administrator.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping Gatekeeper...")
        sys.exit(0)

if __name__ == "__main__":
    main()
