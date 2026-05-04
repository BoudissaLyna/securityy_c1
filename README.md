# 🛡️ DNS Tunnel Sentinel v2.4.1

### Real-Time Machine Learning Intrusion Detection System
**DNS Tunnel Sentinel** is a high-performance, ML-driven cybersecurity suite designed to detect and neutralize DNS tunneling attacks (DNS-over-UDP) in real-time. It combines traditional rule-based heuristics with a state-of-the-art **XGBoost Classifier** to identify data exfiltration and Command & Control (C2) traffic hidden within standard DNS queries.

---

## 🚀 How It Works (Step-by-Step)

### 1. Data Ingestion & Feature Engineering
The system monitors network traffic using two primary methods:
- **Live Sniffing**: Uses `Scapy` (Python) to intercept raw UDP Port 53 packets directly from the network interface.
- **Tshark Extractor**: For high-fidelity analysis, `tshark` (Wireshark) captures traffic and pipes it into a feature extractor that calculates **38 discrete features** per DNS flow.

### 2. Machine Learning Inference
Every intercepted packet is fed into the **XGBoost Inference Engine**:
- **Model**: An XGBoost Classifier trained on thousands of benign and malicious DNS flows.
- **Preprocessing**: Uses a `RobustScaler` pipeline to handle outliers and ensure consistent feature normalization.
- **Decision**: The model provides a prediction (`CLEAN` vs `TUNNEL`) along with a **Confidence Score**.

### 3. Real-Time HUD (The Interface)
The frontend is a **React + Electron** application that acts as a Tactical HUD:
- **WebSocket Bridge**: Results are pushed instantly from the Python backend to the UI.
- **Visual Analytics**: Displays entropy histograms, query length distributions, and beaconing frequency charts.

### 4. Active Defense (The Feedback Loop)
When a threat is identified, the system transitions into a proactive defense state:
- **Manual Blocking**: Administrators can click **BLOCK IP** in the HUD.
- **Backend Enforcement**: The IP is added to a **Local Firewall Blocklist** in the Python kernel. All future traffic from that IP is instantly dropped, simulating a real-world IPS (Intrusion Prevention System).

---

## 🛠️ Testing the System

### 1. Start the Backend
```powershell
python python/capture_engine.py
```
*Loads the ML model and starts the WebSocket/HTTP bridge.*

### 2. Start the HUD
```powershell
npm run electron:dev
```
*Launches the graphical monitoring interface.*

### 3. Generate Test Traffic
- **Simulation**: `python python/ml_test_sim.py` (Sends 30 mixed flows to test the model).
- **Manual Live Test**: `nslookup google.com` or `nslookup random-data.covert.tk`.

---

## 📁 Project Structure
- `python/capture_engine.py`: The "Brain" — ML inference, sniffing, and WebSocket server.
- `python/extractor.py`: High-fidelity feature extraction using Tshark.
- `src/`: React frontend (Tactical HUD components).
- `best_model.joblib`: The trained XGBoost model pipeline.

---
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

