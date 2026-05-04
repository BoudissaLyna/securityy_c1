# DNS Tunnel Sentinel — Active Defense Report

## 1. Overview
This project implements a proactive security posture known as **Active Defense**. Unlike traditional monitors that only log threats, this system identifies malicious DNS tunnels in real-time and provides a direct feedback loop to neutralize the attacking source.

## 2. Detection Engine (The ML Core)
The primary intelligence of the system is a high-performance **XGBoost Classifier**. 
- **Features**: The engine extracts 38 discrete features from every DNS flow (Entropy, TTL variance, packet length ratios, etc.).
- **Decision**: The model assigns a confidence score to every packet. If the probability of a "Tunnel" class exceeds the threshold, the packet is labeled as `BLOCKED`.

## 3. Active Defense Architecture
When a threat is identified by the ML engine, the **Active Defense** pipeline is triggered:

### A. Real-Time Neutralization (Simulation)
When an administrator clicks **"BLOCK IP"** in the HUD:
1. **Command Propagation**: The React UI sends an asynchronous `block_ip` command via WebSocket to the Python backend.
2. **Local Blocklist Insertion**: The Python Capture Engine adds the source IP address to a high-speed memory set (`blocked_ips`).
3. **Traffic Filtering**: Every subsequent packet arriving from that IP is intercepted at the ingest layer, matched against the blocklist, and immediately flagged as `IP MANUALLY BLOCKED (Sentinel)`.

### B. Demonstration Protocol
For testing purposes, the system **simulates** the final firewall trigger. Instead of modifying the system's global routing table, it operates a **Local Firewall Layer** within the application kernel. This ensures the demo is safe but accurately represents how the logic would interface with production firewalls.

## 4. Key Security Benefits
- **Zero-Latency Response**: The blocklist is checked in $O(1)$ time using hash-set lookups.
- **Explainable Decisions**: Every block action is accompanied by the ML model's confidence percentage and feature breakdown.
- **Adaptive Shielding**: Whitelisting allows for human oversight, preventing false positives from disrupting legitimate high-traffic DNS services.

---
*Prepared for 3rd Year Security Project Demonstration — ENSIA 2026*
