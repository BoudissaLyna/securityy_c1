#!/usr/bin/env python3
"""
============================================================
 DNS TUNNEL SENTINEL — tshark Feature Extractor
 Reads tshark CSV from stdin, builds 38 flow-level features,
 and POSTs them to the ML inference bridge on port 8000.

 PIPELINE:
   tshark -i <iface> -f "udp port 53 or tcp port 53" \
     -T fields \
     -e frame.time -e ip.src -e ip.dst \
     -e dns.qry.name -e dns.qry.type -e dns.resp.type \
     -e dns.a -e dns.resp.ttl -e dns.id \
     -e dns.flags -e frame.len \
     -E header=y -E separator=, -E quote=d -l \
     | python3 extractor.py

 REQUIRES:  pip install httpx
============================================================
"""
import sys
import csv
import math
import json
import httpx
import io
from collections import defaultdict, Counter
from datetime import datetime
from statistics import mean, median, mode

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
    "rr_classes": [],          # placeholder (derived from flags)
    "src_ip": "",
    "dst_ip": "",
    "domain": ""
})

# IMPORTANT: must EXACTLY match tshark -e order
FIELDNAMES = [
    "frame.time",
    "ip.src",
    "ip.dst",
    "dns.qry.name",
    "dns.qry.type",
    "dns.resp.type",
    "dns.a",
    "dns.resp.ttl",
    "dns.id",
    "dns.flags",
    "frame.len"
]

# DNS response type numeric → name mapping
RR_TYPE_MAP = {1: "A", 5: "CNAME", 16: "TXT", 28: "AAAA", 2: "NS", 15: "MX"}

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
    """Count vowel→consonant or consonant→vowel transitions."""
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

def update_flow(row):
    src_ip = row.get("ip.src", "")
    dst_ip = row.get("ip.dst", "")
    domain  = row.get("dns.qry.name", "")
    ttl_raw = row.get("dns.resp.ttl", "")
    a_rec   = row.get("dns.a", "")
    rr_type = row.get("dns.resp.type", "")
    flags   = row.get("dns.flags", "")
    pkt_size = safe_int(row.get("frame.len", "0"))

    flow_id = f"{src_ip}-{dst_ip}"
    now = datetime.now().timestamp()

    f = flows[flow_id]
    f["timestamps"].append(now)
    f["src_ip"] = src_ip
    f["dst_ip"] = dst_ip
    f["domain"] = domain

    # Separate outgoing queries from incoming responses by flags
    # DNS response bit is bit 15 of flags (0x8000)
    try:
        flags_int = int(flags, 16) if flags.startswith("0x") else int(flags)
        is_response = bool(flags_int & 0x8000)
    except:
        is_response = False

    if is_response:
        f["recv_sizes"].append(pkt_size)
    else:
        f["packet_sizes"].append(pkt_size)

    # TTL
    try:
        f["ttls"].append(int(ttl_raw))
    except:
        pass

    # A records
    if a_rec:
        f["a_records"].add(a_rec)

    # RR types (response resource record types)
    if rr_type:
        for rt in rr_type.split(","):
            t = safe_int(rt.strip())
            if t:
                f["rr_types"].append(t)

    # RR classes — tshark doesn't expose separately by default,
    # we count unique rr_types as a proxy for rr_class_count
    f["rr_classes"] = list(set(f["rr_types"]))

    return flow_id

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
# SEND
# =========================

def send(features):
    try:
        httpx.post(BACKEND_URL, json=features, timeout=5.0)
    except Exception as e:
        # Fallback: print to stdout so operator can see it
        print(json.dumps({k: v for k, v in features.items() if not k.startswith("_")}))

# =========================
# MAIN LOOP
# =========================

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("frame.time"):
            continue

        reader = csv.DictReader(io.StringIO(line), fieldnames=FIELDNAMES)
        row = next(reader, None)
        if not row:
            continue

        flow_id = update_flow(row)
        features = build_features(flow_id)

        if features:
            send(features)


if __name__ == "__main__":
    main()
