# DNS Tunnel Sentinel — Active Defense Report

## 1. Overview
This project implements a proactive security posture known as **Active Defense**. Unlike traditional monitors that only log threats, this system identifies malicious DNS tunnels in real-time and provides a direct feedback loop to neutralize the attacking source.

## 2. Extraction & Detection Engine
The primary intelligence of the system is driven by a real-time extraction pipeline feeding a high-performance **XGBoost Classifier**. 
- **Packet Interception & Parsing**: The system intercepts UDP port 53 traffic using PyDivert and decodes the packets using Scapy. It tracks bidirectional communication in memory, grouping queries and responses into unified flows.
- **Feature Extraction**: The engine computes 38 discrete flow-level features on the fly. These include statistical packet length metrics (mean, variance, rate), domain lexical properties (entropy, vowel/consonant ratios, consecutive character runs), and DNS-specific features (TTL variance, RR type distribution, distinct A records).
- **Decision Query**: The extracted features are sent to a local backend API. If the ML model classifies the features as "Tunnel" or malicious, the active defense response is triggered.

## 3. Active Defense Architecture (The Gatekeeper)
The system operates as a true inline Intrusion Prevention System (IPS), directly interacting with the Windows Filtering Platform to neutralize threats:

### A. Real-Time Inline Neutralization
When the gatekeeper classifies a flow as a "Tunnel":
1. **Network Interception**: DNS packets are held directly at the network layer.
2. **Verdict Enforcement**: The flow is marked as malicious in a local flow cache. The packet is then physically dropped (not re-injected) to sever the tunnel connection. Subsequent packets within the same flow are automatically dropped in $O(1)$ time without redundant ML inference.
3. **Legitimate Traffic Re-injection**: If a packet belongs to a benign flow, the gatekeeper seamlessly re-injects the packet back into the network stack, ensuring zero disruption to normal DNS operations.

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
