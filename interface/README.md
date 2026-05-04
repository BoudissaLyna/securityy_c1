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
*Developed for 3rd Year Security Specialization — ENSIA 2026*
