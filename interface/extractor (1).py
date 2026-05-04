import sys
import csv
import math
import json
import httpx
import io
from collections import defaultdict, Counter
from datetime import datetime
from statistics import mean, median

BACKEND_URL = "http://127.0.0.1:8000/analyze"

# =========================
# FLOW STORAGE
# =========================
flows = defaultdict(lambda: {
    "timestamps": [],
    "packet_sizes": [],
    "ttls": [],
    "a_records": set(),
    "src_ip": "",
    "dst_ip": "",
    "src_port": "",
    "dst_port": "",
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

# =========================
# SAFE HELPERS
# =========================

def safe_int(x):
    try:
        return int(x)
    except:
        return 0


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
    best = cur = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            cur += 1
            best = max(best, cur)
        else:
            cur = 1
    return best if s else 0


def vowel_consonant_ratio(s):
    vowels = "aeiou"
    v = sum(1 for c in s if c in vowels)
    c = sum(1 for c in s if c.isalpha() and c not in vowels)
    return v / max(c, 1)


def ngrams(s, n):
    return [s[i:i+n] for i in range(len(s)-n+1)]

# =========================
# FLOW UPDATE
# =========================

def update_flow(row):
    src_ip = row.get("ip.src", "")
    dst_ip = row.get("ip.dst", "")

    domain = row.get("dns.qry.name", "")
    ttl = row.get("dns.resp.ttl", "")
    a_record = row.get("dns.a", "")

    pkt_size = safe_int(row.get("frame.len", "0"))

    flow_id = f"{src_ip}-{dst_ip}"
    now = datetime.now().timestamp()

    f = flows[flow_id]
    f["timestamps"].append(now)
    f["packet_sizes"].append(pkt_size)
    f["src_ip"] = src_ip
    f["dst_ip"] = dst_ip
    f["domain"] = domain

    if ttl.isdigit():
        f["ttls"].append(int(ttl))

    if a_record:
        f["a_records"].add(a_record)

    return flow_id

# =========================
# FEATURE BUILDER
# =========================

def build_features(flow_id):
    f = flows[flow_id]

    if len(f["timestamps"]) < 2:
        return None

    t = f["timestamps"]
    sizes = f["packet_sizes"]
    ttls = f["ttls"]
    domain = f["domain"] or ""

    duration = max(t) - min(t)
    total_bytes = sum(sizes)

    mean_size = mean(sizes)
    var = mean([(x - mean_size) ** 2 for x in sizes])
    std = math.sqrt(var)

    labels = domain.split('.') if domain else []
    tld = labels[-1] if len(labels) >= 1 else ""
    sld = labels[-2] if len(labels) >= 2 else ""
    sub = '.'.join(labels[:-2]) if len(labels) > 2 else ""

    ent = entropy(sub)
    num_pct = sum(c.isdigit() for c in sub) / max(len(sub), 1)

    return {
        "flow_id": flow_id,
        "timestamp": min(t),
        "src_ip": f["src_ip"],
        "dst_ip": f["dst_ip"],
        "duration": duration,
        "total_bytes": total_bytes,
        "packets_rate": len(sizes) / max(duration, 1e-6),
        "packets_len_rate": total_bytes / max(duration, 1e-6),
        "min_packets_len": min(sizes),
        "max_packets_len": max(sizes),
        "mean_packets_len": mean_size,
        "standard_deviation_packets_len": std,
        "variance_packets_len": var,
        "coefficient_of_variation_packets_len": std / max(mean_size, 1e-6),
        "dns_domain_name": domain,
        "dns_domain_name_length": len(domain),
        "dns_subdomain_name_length": len(sub),
        "dns_top_level_domain": tld,
        "dns_second_level_domain": sld,
        "character_entropy": ent,
        "numerical_percentage": num_pct,
        "character_distribution": dict(Counter(sub)),
        "max_continuous_numeric_len": max_consecutive(sub, str.isdigit),
        "max_continuous_alphabet_len": max_consecutive(sub, str.isalpha),
        "max_continuous_same_alphabet_len": max_same_char(sub),
        "vowels_consonant_ratio": vowel_consonant_ratio(sub),
        "distinct_ttl_values": len(set(ttls)) if ttls else 0,
        "ttl_values_min": min(ttls) if ttls else -1,
        "ttl_values_max": max(ttls) if ttls else -1,
        "ttl_values_mean": mean(ttls) if ttls else -1,
        "ttl_values_median": median(ttls) if ttls else -1,
        "distinct_A_records": len(f["a_records"])
    }

# =========================
# SEND
# =========================

def send(features):
    try:
        httpx.post(BACKEND_URL, json=features, timeout=5.0)
    except:
        print(json.dumps(features))

# =========================
# MAIN LOOP
# =========================

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("frame.time"):
            continue

        reader = csv.DictReader(io.StringIO(line), fieldnames=FIELDNAMES)
        row = next(reader)

        flow_id = update_flow(row)
        features = build_features(flow_id)

        if features:
            send(features)


if __name__ == "__main__":
    main()

