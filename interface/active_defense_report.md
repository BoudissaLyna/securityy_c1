# DNS Tunnel Sentinel — Active Defense Report

## 1. Overview
This project implements a proactive security posture known as **Active Defense**. Unlike traditional monitors that only log threats, this system identifies malicious DNS tunnels in real-time and provides a direct feedback loop to neutralize the attacking source.

## 2. Detection Engine (The ML Core)
The primary intelligence of the system is a high-performance **XGBoost Classifier**. 
- **Features**: The engine extracts 38 discrete features from every DNS flow (Entropy, TTL variance, packet length ratios, etc.).
- **Decision**: The model assigns a confidence score to every packet. If the probability of a "Tunnel" class exceeds the threshold, the packet is labeled as `BLOCKED`.

## 3. Active Defense Architecture
When a threat is identified by the ML engine, the **Active Defense** pipeline is triggered:

### A. Real-Time Automated Neutralization
When the ML engine classifies a flow as a "Tunnel":
1. **Network Interception**: The active gatekeeper intercepts DNS packets directly at the network layer using the Windows Filtering Platform (via PyDivert).
2. **Verdict Enforcement**: The flow is marked as malicious, and the packet is physically dropped to sever the tunnel connection. Subsequent packets within the same flow are automatically dropped without redundant ML inference.
3. **Traffic Elimination**: The gatekeeper operates as a true inline Intrusion Prevention System (IPS), silently discarding malicious packets while seamlessly re-injecting legitimate traffic back into the network stack.

### B. Manual Administrator Intervention
When an administrator clicks **"BLOCK IP"** in the HUD:
1. **Command Propagation**: The React UI sends an asynchronous `block_ip` command via WebSocket to the Python backend.
2. **Local Blocklist Insertion**: The Python engine adds the source IP address to a high-speed memory set (`blocked_ips`).
3. **Active Filtering**: Every subsequent packet arriving from that IP is matched against the blocklist and immediately dropped by the active defense layer.

### C. True Inline Active Defense
The system has been upgraded from a simulated alert mechanism to an actual **Inline Firewall Layer**. Rather than merely flagging threats in a localized dashboard, it directly interacts with the OS network stack to neutralize DNS tunneling attempts in the wild.

## 4. Key Security Benefits
- **Zero-Latency Response**: The blocklist is checked in $O(1)$ time using hash-set lookups.
- **Explainable Decisions**: Every block action is accompanied by the ML model's confidence percentage and feature breakdown.
- **Adaptive Shielding**: Whitelisting allows for human oversight, preventing false positives from disrupting legitimate high-traffic DNS services.

---
*Prepared for 3rd Year Security Project Demonstration — ENSIA 2026*
