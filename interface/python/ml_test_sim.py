#!/usr/bin/env python3
"""
============================================================
 DNS TUNNEL SENTINEL — ML Model Test Simulator
 
 Generates fake DNS flow features and sends them directly
 to the capture engine bridge (port 8000), which runs them
 through the XGBoost model and pushes results to the UI.

 HOW TO USE:
   1. Start capture_engine.py   (Terminal 1)
   2. Start the UI               (Terminal 2)
   3. Run this script            (Terminal 3)

 No admin, no tshark, no Scapy needed — just tests the model.
============================================================
"""
import json
import time
import random
import string
import math
import httpx
from collections import Counter
from statistics import mean, median

BRIDGE_URL = "http://127.0.0.1:8000/analyze"

# ── Helpers ──

def entropy(s):
    if not s:
        return 0.0
    freq = Counter(s)
    l = len(s)
    return -sum((c / l) * math.log2(c / l) for c in freq.values())

def max_consecutive(s, cond):
    best = cur = 0
    for c in s:
        if cond(c):
            cur += 1; best = max(best, cur)
        else:
            cur = 0
    return best

def max_same_char(s):
    if not s: return 0
    best = cur = 1
    for i in range(1, len(s)):
        if s[i] == s[i-1]: cur += 1; best = max(best, cur)
        else: cur = 1
    return best

def is_consonant(c):
    return c.isalpha() and c.lower() not in "aeiou"

def vowel_consonant_ratio(s):
    v = sum(1 for c in s if c.lower() in "aeiou")
    con = sum(1 for c in s if c.isalpha() and c.lower() not in "aeiou")
    return v / max(con, 1)

def conv_freq(s):
    if len(s) < 2: return 0
    vowels = set("aeiouAEIOU")
    t = 0
    for i in range(1, len(s)):
        if s[i-1].isalpha() and s[i].isalpha():
            if (s[i-1] in vowels) != (s[i] in vowels):
                t += 1
    return t


# ── Generate benign flow ──

def make_benign():
    domains = [
        "google.com", "facebook.com", "youtube.com", "wikipedia.org",
        "github.com", "cloudflare.com", "microsoft.com", "amazon.com",
        "ensia.edu.dz", "reddit.com", "stackoverflow.com", "apple.com",
    ]
    domain = random.choice(domains)
    labels = domain.split(".")
    sub = ".".join(labels[:-2]) if len(labels) > 2 else ""
    ttls = [random.randint(60, 3600) for _ in range(random.randint(1, 3))]
    sizes = [random.randint(40, 120) for _ in range(random.randint(2, 5))]
    duration = random.uniform(0.01, 0.5)

    return _build_features(domain, sub, sizes, ttls, duration,
                           recv_bytes=sum(random.randint(40, 200) for _ in sizes),
                           rr_types=[1], a_records=1)


# ── Generate tunnel flow ──

def make_tunnel():
    # High-entropy random subdomain like real DNS tunnel
    sub_len = random.randint(20, 60)
    sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=sub_len))
    base = random.choice(["evil-c2.xyz", "exfil.io", "covert.tk", "tunnel.ml", "c2-drop.net"])
    domain = f"{sub}.{base}"
    
    ttls = [random.randint(0, 30) for _ in range(random.randint(3, 10))]
    sizes = [random.randint(100, 512) for _ in range(random.randint(10, 50))]
    duration = random.uniform(2.0, 30.0)

    return _build_features(domain, sub, sizes, ttls, duration,
                           recv_bytes=sum(random.randint(100, 500) for _ in sizes),
                           rr_types=[1, 16, 5],  # A + TXT + CNAME
                           a_records=random.randint(3, 15))


# ── Build the 38 features dict ──

def _build_features(domain, sub, sizes, ttls, duration, recv_bytes, rr_types, a_records):
    total_bytes = sum(sizes)
    mean_size = mean(sizes)
    var = mean([(x - mean_size)**2 for x in sizes])
    std = math.sqrt(var)
    labels = domain.split(".")

    rr_set = set(rr_types)

    def safe_mode(vals):
        if not vals: return -1
        return Counter(vals).most_common(1)[0][0]

    return {
        "duration":                         round(duration, 4),
        "total_bytes":                      total_bytes,
        "receiving_bytes":                  recv_bytes,
        "packets_rate":                     round(len(sizes) / max(duration, 1e-6), 2),
        "packets_len_rate":                 round(total_bytes / max(duration, 1e-6), 2),
        "min_packets_len":                  min(sizes),
        "max_packets_len":                  max(sizes),
        "mean_packets_len":                 round(mean_size, 2),
        "standard_deviation_packets_len":   round(std, 2),
        "dns_domain_name_length":           len(domain),
        "dns_subdomain_name_length":        len(sub),
        "numerical_percentage":             round(sum(c.isdigit() for c in sub) / max(len(sub), 1), 4),
        "character_entropy":                round(entropy(sub), 4),
        "max_continuous_numeric_len":       max_consecutive(sub, str.isdigit),
        "max_continuous_alphabet_len":      max_consecutive(sub, str.isalpha),
        "max_continuous_consonants_len":    max_consecutive(sub, is_consonant),
        "max_continuous_same_alphabet_len": max_same_char(sub),
        "vowels_consonant_ratio":           round(vowel_consonant_ratio(sub), 4),
        "conv_freq_vowels_consonants":      conv_freq(sub),
        "distinct_ttl_values":              len(set(ttls)),
        "ttl_values_min":                   min(ttls) if ttls else -1,
        "ttl_values_max":                   max(ttls) if ttls else -1,
        "ttl_values_mean":                  round(mean(ttls), 2) if ttls else -1,
        "ttl_values_mode":                  safe_mode(ttls),
        "ttl_values_median":                round(median(ttls), 2) if ttls else -1,
        "distinct_A_records":               a_records,
        "rr_type_count":                    len(rr_types),
        "rr_type_has_A":                    int(1 in rr_set),
        "rr_type_has_CNAME":                int(5 in rr_set),
        "rr_type_has_TXT":                  int(16 in rr_set),
        "rr_type_unique":                   len(rr_set),
        "rr_class_count":                   len(rr_set),
        "num_dots":                         domain.count("."),
        "subdomain_depth":                  len(labels) - 2 if len(labels) > 2 else 0,
        "digit_ratio":                      round(sum(c.isdigit() for c in sub) / max(len(sub), 1), 4),
        "letter_ratio":                     round(sum(c.isalpha() for c in sub) / max(len(sub), 1), 4),
        "special_char_count":               sum(1 for c in sub if not c.isalnum() and c != "."),
        "unique_chars":                     len(set(sub)) if sub else 0,
        # Metadata for the UI
        "_src_ip":  f"10.0.0.{random.randint(2, 254)}",
        "_dst_ip":  "8.8.8.8",
        "_domain":  domain,
    }


# ── Main ──

def main():
    print("=" * 60)
    print("  DNS TUNNEL SENTINEL — ML Model Test Simulator")
    print("=" * 60)
    print()
    print("Sending 30 flows to the ML bridge (port 8000)...")
    print("  - 15 benign (google.com, etc.)")
    print("  - 15 tunnel (high-entropy subdomains)")
    print()

    flows = []
    for _ in range(15):
        flows.append(("BENIGN", make_benign()))
    for _ in range(15):
        flows.append(("TUNNEL", make_tunnel()))
    random.shuffle(flows)

    success = 0
    fail = 0

    for i, (label, features) in enumerate(flows, 1):
        domain = features["_domain"]
        ent = features["character_entropy"]
        short_domain = domain if len(domain) < 45 else domain[:42] + "..."

        try:
            resp = httpx.post(BRIDGE_URL, json=features, timeout=5.0)
            status = "OK" if resp.status_code == 200 else f"ERR {resp.status_code}"
            success += 1
        except Exception as e:
            status = f"FAIL ({e})"
            fail += 1

        print(f"  [{i:02d}/30] {label:7s} | ent={ent:.2f} | {short_domain:45s} | {status}")
        time.sleep(0.3)  # Small delay so UI can show packets arriving

    print()
    print(f"Done! {success} sent, {fail} failed.")
    print("Check the Sentinel UI — you should see CLEAN and BLOCKED packets.")
    print()


if __name__ == "__main__":
    main()
