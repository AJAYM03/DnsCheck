# DNS Spoofing Detection & Alert System

A **real-time network security monitoring tool** designed to detect DNS spoofing attacks using **stateful inspection and metadata-based heuristics**.  
Unlike basic detectors that rely only on IP matching, this system analyzes **DNS response behavior** (TTL anomalies, unsolicited replies, and transaction mismatches) to identify attacks such as **Cache Poisoning** and **Blind DNS Spoofing**.

Built using **Python, Scapy, Flask, Socket.IO, and SQLite**, the system provides a live monitoring dashboard, persistent attack history, and instant **Telegram alert notifications**.

---

## 🚀 Key Features

### 🛡️ Advanced Detection Logic
- **TTL & Metadata Analysis:** Detects abnormal TTL values that may indicate cache poisoning attempts.
- **Stateful DNS Inspection:** Tracks outgoing DNS queries to identify **unsolicited or injected responses**.
- **IP Verification:** Compares DNS responses against trusted records and validates results using **Google Public DNS**.

### ⚡ Real-Time Monitoring
- **Live Dashboard:** WebSocket-powered interface with instant updates (no page refresh).
- **Telegram Alerts:** Sends immediate push notifications when suspicious or malicious DNS activity is detected.
- **Visual & Audio Alerts:** Color-coded dashboard entries with optional siren alerts for critical events.

### 💾 Logging & Forensics
- **Persistent Storage:** Logs all DNS events (safe and malicious) into a **SQLite database**.
- **History View:** Browse and review past DNS activity using the dashboard’s History tab.

---

## 🛠️ Tech Stack

- **Packet Capture:** Python 3, Scapy  
- **Backend:** Flask, Flask-SocketIO (threading mode)  
- **Database:** SQLite, SQLAlchemy  
- **Frontend:** HTML, Bootstrap 5, JavaScript (WebSockets)  
- **Alerts:** Telegram Bot API  

---

## 📦 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/AJAYM03/DnsCheck.git
cd DnsCheck
```

### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 3️⃣ Configuration
- Open `config.py`
  - Add your **Telegram Bot Token** and **Chat ID**
  - (Use `get_chat_id.py` if required)
- Update `trusted_domains.json`
  - Configure trusted domains, IPs, and expected TTL ranges

---

## 🚦 Usage

### ▶️ Start the Detector
Run the main application:
```bash
python app.py
```

- The system will prompt for network interface selection (Wi-Fi / Loopback).
- Open the dashboard at:
```
http://localhost:5001
```

---

### 🧪 Simulate Attacks (Testing)
In a separate terminal, run the simulator:
```bash
python simulate.py
```

Available test modes:
1. **Standard IP Spoofing** – basic validation test  
2. **TTL Manipulation** – tests metadata-based detection  
3. **Blind Injection** – tests unsolicited response detection  

---

## 📊 Detection Workflow

1. **Packet Capture:** Listens for DNS traffic on the selected interface.
2. **Context Validation:**
   - Was this DNS response expected?
   - Does the Transaction ID match an outgoing request?
3. **Heuristic Analysis:**
   - IP legitimacy check
   - TTL range validation
4. **Response Handling:**
   - **Safe:** Logged and displayed as normal traffic
   - **Attack:** Logged, highlighted on dashboard, and sent as a Telegram alert

---

## 📜 License

This project is released under the **MIT License** and is intended for **educational and research purposes**.

---

## ⚠️ Disclaimer
This tool is designed for learning, experimentation, and controlled testing environments.  
Do **not** deploy on networks without proper authorization.

