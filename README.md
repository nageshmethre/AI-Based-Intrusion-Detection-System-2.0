# AI-Based Network Intrusion Detection System (CyberSOC IDS)

A functional, real-time AI-based Network Intrusion Detection System featuring live packet sniffing, bidirectional flow aggregation, a Random Forest classifier trained on CIC-IDS2017 flow distributions, deterministic rule engines (Port Scan, SYN Flood, and SSH Auth Brute-Force), chunk-based authentic dataset import support, an interactive Guide & Help Center, an asynchronous FastAPI + SQLite backend, and a cybersecurity SOC dashboard in React with Tailwind CSS, Recharts, and WebSockets.

---

## 1. System Architecture

```
                                  +-----------------------------------------------+
                                  |         Live Network Traffic (Scapy)          |
                                  +-----------------------------------------------+
                                                          |
                                                          v
                                  +-----------------------------------------------+
                                  |           PacketSniffer & Ingestion           |
                                  |  - Discovers Wi-Fi, Ethernet & Loopback NICs  |
                                  |  - Extracts IP/IPv6, TCP, UDP, ICMP headers   |
                                  |  - Tracks per-packet flags and lengths        |
                                  +-----------------------------------------------+
                                          /                               \
                                         /                                 \
                                        v                                   v
             +--------------------------------------+      +--------------------------------+
             |   Rule-Based Detection Engine        |      |      FlowAggregator            |
             |   - Port Scan (Sliding window)       |      | - Canonical 5-tuple matching   |
             |   - SYN Flood burst detection        |      | - Bidirectional flow tracking  |
             |   - SSH Brute Force monitor          |      | - 40 CIC-IDS2017 features      |
             +--------------------------------------+      +--------------------------------+
                                        \                                   |
                                         \                                  v
                                          \        +----------------------------------------+
                                           \       |          AI Detection Engine           |
                                            \      | - Random Forest Classifier             |
                                             \     | - RobustScaler preprocessing           |
                                              \    | - Confidence >= 0.80 & Margin >= 0.25  |
                                               \   +----------------------------------------+
                                                \                 /
                                                 v               v
                                  +-----------------------------------------------+
                                  |         FastAPI Core & SQLite Database        |
                                  |  - Tables: NetworkEvents, ThreatAlerts, Logs  |
                                  |  - REST Endpoints (/api/overview, /status)    |
                                  +-----------------------------------------------+
                                                          |
                                                          v
                                  +-----------------------------------------------+
                                  |       WebSocket Broadcaster (/ws/soc)         |
                                  |  - TRAFFIC_PULSE (1s telemetry metrics)       |
                                  |  - NEW_EVENT (live analyzed flows)            |
                                  |  - NEW_ALERT (real-time threat alerts)        |
                                  +-----------------------------------------------+
                                                          |
                                                          v
                                  +-----------------------------------------------+
                                  |         React SOC Dashboard (Tailwind)        |
                                  |  1. Security Overview                         |
                                  |  2. Live Network Monitoring                   |
                                  |  3. Threat Detection (Incident Response)      |
                                  |  4. AI Model Performance (Confusion Matrix)   |
                                  |  5. Security Logs & SSH Ingestion Console     |
                                  |  6. Settings & Adapter Switcher               |
                                  |  7. Guide & Help Center (Interactive Docs)    |
                                  +-----------------------------------------------+
```

---

## 2. Technology Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn, Scapy, Pandas, NumPy, Scikit-learn, SQLite, SQLAlchemy, Joblib, WebSockets.
- **Frontend**: React.js 19, Vite, Tailwind CSS, Recharts, Lucide Icons.
- **Machine Learning**: Random Forest Classifier with 40 CIC-IDS2017 bidirectional flow features, RobustScaler, Stratified train/test validation, and False Positive Rate (FPR) tracking.
- **OS Compatibility**: Native Windows 11 with Npcap driver and Linux.

---

## 3. Authentic CIC-IDS2017 Dataset Support

### Official Source & Citations
- **Institution**: Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB), Fredericton, Canada.
- **Dataset Title**: Intrusion Detection Evaluation Dataset (CIC-IDS2017)
- **Authors**: Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani (ICISSP 2018).
- **Official UNB Webpage**: [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Kaggle Mirror**: [https://www.kaggle.com/datasets/cicdataset/cicids2017](https://www.kaggle.com/datasets/cicdataset/cicids2017)
- **Official CSV Archive**: `GeneratedLabelledFlows.zip`

### Supported 8 Official Daily CSV Files:
1. `Monday-WorkingHours.pcap_ISCX.csv` (Pure Benign baseline traffic)
2. `Tuesday-WorkingHours.pcap_ISCX.csv` (FTP-Patator, SSH-Patator brute force)
3. `Wednesday-workingHours.pcap_ISCX.csv` (DoS slowloris, DoS Slowhttptest, DoS Hulk, DoS GoldenEye, Heartbleed)
4. `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` (Web attacks: Brute Force, XSS, Sql Injection)
5. `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` (Infiltration)
6. `Friday-WorkingHours-Morning.pcap_ISCX.csv` (Botnet: ARES)
7. `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` (PortScan: Nmap)
8. `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (DDoS: LOIC)

### How to Import & Process Authentic CSV Files
1. Download `GeneratedLabelledFlows.zip` from UNB or Kaggle.
2. Extract any or all of the 8 CSV files into the raw directory:
   ```
   backend/data/raw/
   ```
3. Run the chunk-based compilation pipeline (or click **"Compile Authentic CSVs"** in the **AI Model Performance** page):
   ```powershell
   python -c "from backend.app.ml.dataset_importer import process_authentic_cicids2017; process_authentic_cicids2017()"
   ```
   *The chunk processor streams data in 50,000-row chunks, removes whitespace, sanitizes NaNs and infinities, eliminates duplicate records, maps labels across all attack categories, and balances classes via stratified reservoir sampling without exceeding system RAM.*
4. Retrain the model on the authentic dataset:
   ```powershell
   python -m backend.app.ml.train
   ```

---

## 4. Guide & Help Center (Interactive SOC Knowledge Base)

The application includes an integrated **Guide & Help Center** directly in the navigation console:

1. **Live Project Diagnostics**: Real-time status cards verifying the Backend, Frontend, Packet Capture, Adapter, AI Model, Dataset Provenance, SQLite Database, and WebSocket Stream.
2. **Getting Started**: What is this application, core objectives, how the real-time AI IDS operates, step-by-step starting and stopping instructions.
3. **System Architecture**: Detailed breakdown from raw network packet to Scapy sniffer, 5-tuple flow reassembly, 40 statistical features, AI & Rule engines, SQLite database, and WebSocket broadcast.
4. **Dashboard Guide**: Visual dictionary explaining Throughput (pps), Active Flows, Severity levels, Open alerts, Confidence, and Margin.
5. **Live Monitoring Guide**: Windows Npcap architecture rules, switching between Wi-Fi and Npcap Loopback, starting/stopping capture.
6. **AI Model Guide**: Random Forest deep-dive, what is CIC-IDS2017, how the model is trained, decision trees, Accuracy, Precision, Recall, F1-Score, and False Positive Rate.
7. **Threat Detection Guide**: Port scanning (SYN sweeps), DoS/DDoS (Hulk, GoldenEye, LOIC), Brute Force (SSH/FTP Patator), Botnets, and how dual thresholds eliminate HTTPS false alarms.
8. **Testing & Demonstration Guide**: Copyable commands and expected outputs for isolated port scans, SSH auth failure ingestion, and normal web browsing tests.
9. **Database & Security Logs Guide**: Schema explanation for `network_events`, `threat_alerts`, and `system_logs`.
10. **Troubleshooting Guide**: Remediation for Npcap missing, administrator permission errors, loopback packet routing, and connection drops.
11. **Frequently Asked Questions (FAQ)**: Essential technical questions and model answers for MCA evaluation panels.

---

## 5. Directory Structure

```
ai-based-intrusion-detection-system/
│
├── backend/
│   ├── app/
│   │   ├── config.py                 # Global settings, paths, dual ML thresholds
│   │   ├── main.py                   # FastAPI app, static mount & lifecycle
│   │   ├── api/
│   │   │   ├── routes.py             # REST endpoints (overview, threats, events, logs, dataset, system)
│   │   │   └── websockets.py         # Thread-safe WebSocket connection manager
│   │   ├── capture/
│   │   │   ├── flow.py               # Bidirectional flow aggregator & 40-feature extractor
│   │   │   └── sniffer.py            # Scapy live packet capture thread & adapter switcher
│   │   ├── database/
│   │   │   ├── connection.py         # SQLite engine (WAL mode) & session generator
│   │   │   └── models.py             # SQLAlchemy models (NetworkEvent, ThreatAlert, SystemLog)
│   │   ├── ml/
│   │   │   ├── schema.py             # CIC-IDS2017 canonical feature definitions & attack labels
│   │   │   ├── preprocessor.py       # Imputation, NaN/inf cleaning, RobustScaler
│   │   │   ├── dataset_importer.py   # Authentic UNB chunk-based processor & scanner
│   │   │   ├── dataset_builder.py    # Standard flow dataset generator
│   │   │   ├── train.py              # Random Forest training, evaluation & FPR computation
│   │   │   └── detector.py           # Real-time inference engine with dual-gate threshold
│   │   └── rules/
│   │       ├── port_scan.py          # Port scan detection rule (sliding window)
│   │       ├── abnormal_conn.py      # SYN flood detection rule
│   │       ├── ssh_monitor.py        # SSH brute-force monitor
│   │       └── rule_engine.py        # Unified rule orchestrator
│   ├── data/
│   │   ├── raw/                      # Authentic CIC-IDS2017 CSV files (drop UNB CSVs here)
│   │   ├── processed/                # Sanitized authentic & augmented training sets
│   │   ├── dataset_manifest.json     # Authentic dataset metadata & provenance
│   │   └── soc_ids.db                # SQLite database (WAL mode)
│   ├── saved_models/                 # Random forest & scaler joblib artifacts
│   └── tests/                        # Automated verification test suites
│
├── frontend/                         # React SOC Dashboard
│   ├── src/
│   │   ├── components/
│   │   │   ├── Sidebar.jsx           # SOC Navigation sidebar
│   │   │   ├── Header.jsx            # Top bar with throughput, active NIC pill & Help button
│   │   │   ├── ContextHelp.jsx       # Reusable contextual help tooltip/popover
│   │   │   ├── HelpDrawer.jsx        # Interactive sliding help drawer with search & commands
│   │   │   └── ProjectStatus.jsx     # Live runtime subsystem telemetry dashboard
│   │   ├── pages/
│   │   │   ├── SecurityOverview.jsx  # Primary SOC telemetry & charts
│   │   │   ├── LiveMonitoring.jsx    # Live flow table & filtering
│   │   │   ├── ThreatDetection.jsx   # Threat alerts & incident response
│   │   │   ├── ModelPerformance.jsx  # Accuracy, F1, FPR, confusion matrix, authentic dataset
│   │   │   ├── SecurityLogs.jsx      # Audit logs & SSH failure simulator
│   │   │   ├── SettingsPage.jsx      # Interface switcher & threshold tuning
│   │   │   └── GuideHelpCenter.jsx   # Full 11-chapter interactive knowledge center
│   │   └── services/api.js           # REST & WebSocket client
│   └── dist/                         # Compiled production assets (Vite)
│
├── requirements.txt                  # Python dependencies
├── test_traffic_generator.py         # Authorized local test traffic script
└── README.md                         # Project documentation
```

---

## 6. Setup and Execution Instructions (Windows 11)

### Step 1: Prerequisites
1. **Python 3.10+**: Ensure Python is installed and added to `PATH`.
2. **Npcap**: For live Windows packet sniffing, ensure [Npcap](https://npcap.com/) is installed (enable "WinPcap API-compatible mode" during installation).
3. **Node.js 18+**: Required only if modifying or recompiling the React frontend.

### Step 2: Install Python Dependencies
Open PowerShell as Administrator:
```powershell
python -m pip install -r requirements.txt
```

### Step 3: Run the Complete SOC Application
You can run the full-stack system (FastAPI backend + integrated React SOC frontend) with one command:
```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```
Open your browser and navigate to:
```
http://127.0.0.1:8000
```

---

## 7. Demonstration Guide for MCA Project Evaluation

### Demo 1: Genuine Local Port Scan Detection
1. Open the dashboard at `http://127.0.0.1:8000`.
2. Navigate to **Settings** and click **"Npcap Loopback"** (or use the command below):
   ```powershell
   python -c "import urllib.request, json; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/api/settings', data=json.dumps({'network_interface': r'\Device\NPF_Loopback'}).encode(), headers={'Content-Type': 'application/json'}))"
   ```
3. Execute the safe port scan simulation:
   ```powershell
   python test_traffic_generator.py --mode portscan
   ```
4. **Result**: An immediate `HIGH` severity **"Port Scanning Activity Detected"** alert appears on the dashboard with the scanned ports sample and source IP `127.0.0.1`.

### Demo 2: SSH Brute Force Ingestion
1. Navigate to **Security Logs**.
2. Click **"Simulate 6x SSH Auth Failures"** or run:
   ```powershell
   python -c "import urllib.request, json; [urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/api/logs/ingest', data=json.dumps({'log_line': 'Failed password for root from 198.51.100.44 port 42100 ssh2'}).encode(), headers={'Content-Type': 'application/json'})) for _ in range(5)]"
   ```
3. **Result**: A `HIGH` severity **"SSH Authentication Brute Force Attack Detected"** alert triggers automatically.

### Demo 3: Normal HTTPS Traffic (Zero False Positives)
1. In **Settings**, switch back to **Default (Wi-Fi)**.
2. Browse regular web pages or run `python test_traffic_generator.py --mode benign`.
3. **Result**: Network events increment in the Live Monitoring table, but zero false positive DoS alerts are added due to the `confidence >= 0.80` and `margin >= 0.25` thresholds.

---

## 8. License & Attribution

This project is developed for academic and educational evaluation. Network flow statistical definitions and schemas are derived from the Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB).
