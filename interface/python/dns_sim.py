#!/usr/bin/env python3
"""
============================================================
 DNS TUNNEL SENTINEL — Traffic Simulator
 Generates test DNS traffic to validate the capture pipeline.

 Fires 50 DNS queries — roughly half to legitimate domains
 and half to randomly-generated subdomains that mimic DNS
 tunneling (high entropy, long subdomain, DGA-like names).

 Run this WHILE capture_engine.py or tshark | extractor.py
 is active so you can see the detections fire in the UI.

 NOTE: Uses 'nslookup' on Windows, 'dig' on Linux/macOS.
       Suppresses all output from the DNS commands.
============================================================
"""
import os
import sys
import random
import string


def normal():
    """Return a benign, well-known domain."""
    domains = ["google.com", "ensia.edu.dz", "facebook.com", "wikipedia.org",
               "github.com", "cloudflare.com", "microsoft.com"]
    return random.choice(domains)


def malicious():
    """Return a randomly generated high-entropy subdomain (mimics DNS tunnel)."""
    sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=25))
    return f"{sub}.evil.com"


def dns_query(domain):
    """Issue a DNS query suppressing output. Cross-platform."""
    if sys.platform == "win32":
        os.system(f"nslookup {domain} > nul 2>&1")
    else:
        os.system(f"dig {domain} > /dev/null 2>&1")


if __name__ == "__main__":
    print(f"[DNS SIM] Firing 50 DNS queries (mix of benign + tunnel-like)...")
    for i in range(50):
        domain = normal() if random.random() < 0.5 else malicious()
        print(f"  [{i+1:02d}/50] {domain}")
        dns_query(domain)
    print("[DNS SIM] Done.")
