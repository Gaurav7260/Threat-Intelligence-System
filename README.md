# 🛡️ Enterprise Threat Intelligence & Real-Time SOC Detection System

An enterprise-grade Security Operations Center (SOC) platform and Threat Intelligence Aggregator built with **Python**, **Streamlit**, and **FastAPI**. The system provides real-time endpoint process monitoring, macOS unified system log ingestion, automated IP reputation enrichment via **AbuseIPDB** & **VirusTotal**, risk scoring, MITRE ATT&CK mapping, and automated PDF incident report generation.

---

## 📑 Table of Contents

- [Overview & Architecture](#-overview--architecture)
- [Key Features](#-key-features)
- [Tech Stack & Tools](#-tech-stack--tools)
- [Project Directory Structure](#-project-directory-structure)
- [Authentication & Credentials](#-authentication--credentials)
- [Prerequisites & Installation](#-prerequisites--installation)
- [Configuration (.env)](#-configuration-env)
- [How to Run (Step-by-Step Guide)](#-how-to-run-step-by-step-guide)
- [Testing & Simulating Threat Alerts](#-testing--simulating-threat-alerts)
- [Threat Intelligence Enrichment Pipeline](#-threat-intelligence-enrichment-pipeline)
- [Backend REST API Reference](#-backend-rest-api-reference)
- [Docker Deployment](#-docker-deployment)
- [Troubleshooting & FAQs](#-troubleshooting--faqs)

---

## 🏗️ Overview & Architecture

```
                                  +---------------------------------------+
                                  |         macOS Unified Logs /          |
                                  |       Running Process Activity        |
                                  +-------------------+-------------------+
                                                      |
                         +----------------------------+----------------------------+
                         |                                                         |
                         v                                                         v
          [ mac_failed_password_monitor.py ]                             [ real_time_agent.py ]
          - Streams macOS `log stream`                                    - Uses `psutil`
          - Detects sudo failures & auth errors                          - Flags suspicious tools (nmap, nc, etc.)
                         |                                                         |
                         +----------------------------+----------------------------+
                                                      |
                                                      v
                                      +-------------------------------+
                                      |   datasets/realtime_alerts.csv |
                                      +---------------+---------------+
                                                      |
                                                      v
+------------------------------------+  +-------------+--------------+  +------------------------------------+
|    Threat Intelligence Pipeline    |  |       SOC Dashboard        |  |        FastAPI Backend API         |
|  - api/enrich_logs.py (AbuseIPDB)  |->|      (dashboard/app.py)    |<-|        (backend/api.py)            |
|  - api/virustotal_lookup.py (VT)   |  |   - Streamlit Cyber UI     |  |   - SQLite alerts.db               |
+------------------------------------+  |   - Live Auto-refresh (5s) |  |   - JWT Authentication             |
                                        |   - MITRE ATT&CK Mapping   |  |   - GET /alerts                    |
                                        |   - Geo-IP Threat Globe    |  +------------------------------------+
                                        |   - PDF Report Generator   |
                                        +----------------------------+
```

---

## ✨ Key Features

- **🔴 Real-Time macOS System Log Ingestion:** Captures live macOS authentication and failed `sudo` attempts via native `log stream`.
- **⚡ Endpoint Process Monitoring:** Continuously scans running processes using `psutil` to detect offensive security tools (`nmap`, `wireshark`, `tcpdump`, `sqlmap`, `hydra`, `netcat`, `nc`, `john`, `hashcat`).
- **🌐 Threat Intelligence Enrichment:** Automatically checks public IPs against **AbuseIPDB** (abuse confidence score, ISP, country, Tor status) and **VirusTotal** API v3.
- **📊 Interactive SOC Cyber Command Center:** Modern dark-mode UI with live KPI counters, auto-refreshing alert feeds, risk severity gauges, and attack distribution charts.
- **🗺️ Threat Intelligence Globe & Geo-IP:** Interactive geospatial visual mapping of threat origins and country distributions.
- **🎯 MITRE ATT&CK Mapping:** Classifies detected threats into standard MITRE tactics and techniques.
- **📄 Automated PDF Incident Reports:** Generates professional executive summary PDF incident reports with a single click.
- **🔌 FastAPI Backend & SQLite Database:** High-performance RESTful API with SQLite persistence and JWT token authentication.

---

## 🛠️ Tech Stack & Tools

| Component | Technologies & Libraries |
| :--- | :--- |
| **Frontend / Dashboard** | Python 3.11+, Streamlit, Plotly Express/Graph Objects, Streamlit-Autorefresh, Altair |
| **Backend REST API** | FastAPI, Uvicorn, Starlette, Pydantic, Python-JOSE (JWT), SQLite3 |
| **System & Log Monitoring** | `psutil`, macOS `log stream` subsystem, `subprocess`, Python `csv` |
| **Threat Intelligence APIs** | AbuseIPDB REST API v2, VirusTotal API v3, `requests`, `python-dotenv` |
| **Data Processing & Analytics** | Pandas, NumPy, PyArrow |
| **Reporting & Export** | FPDF (PDF generator) |
| **Containerization** | Docker |

---

## 📂 Project Directory Structure

```
Threat-Intelligence-System/
├── .env                               # API keys configuration (AbuseIPDB, VirusTotal)
├── .gitignore                         # Git ignore rules
├── Dockerfile                         # Root Docker configuration
├── README.md                          # Comprehensive project documentation
├── requirements.txt                   # Python package dependencies
├── malicious_test.py                  # Standalone test script for alert triggering
│
├── api/                               # Threat Intelligence & Log Enrichment Scripts
│   ├── enrich_logs.py                 # Enriches endpoint CSV logs with AbuseIPDB data
│   ├── mac_failed_login_monitor.py    # Terminal demo for simulating failed logins
│   ├── threat_intel.py                # Standalone AbuseIPDB lookup script
│   └── virustotal_lookup.py           # VirusTotal IP reputation lookup script
│
├── backend/                           # FastAPI REST Backend & Database
│   ├── __init__.py
│   ├── alerts.db                      # SQLite alerts database
│   ├── api.py                         # FastAPI server (/alerts, /login)
│   ├── attack_simulator.py            # Random attack event generator into SQLite
│   ├── database.py                    # SQLite schema initialization and CRUD queries
│   ├── jwt_auth.py                    # JWT token creation & authentication
│   └── test_insert.py                 # Backend database verification test script
│
├── dashboard/                         # Streamlit Frontend & Host Agents
│   ├── Dockerfile                     # Dashboard specific Dockerfile
│   ├── app.py                         # Main Streamlit SOC Dashboard Application
│   ├── auth.py                        # Streamlit session-state login mechanism
│   └── agent/
│       ├── mac_failed_password_monitor.py  # macOS log stream monitor for failed sudo
│       ├── malicious_test.py               # Local test process trigger
│       └── real_time_agent.py              # psutil live process monitor
│
├── datasets/                          # Threat Intelligence & Alert Datasets (CSV)
│   ├── ddos_risk_logs.csv             # DDoS attack simulation log dataset
│   ├── endpoint_risk_logs.csv         # Raw endpoint event logs
│   ├── enriched_endpoint_logs.csv     # AbuseIPDB enriched endpoint dataset
│   ├── evtx_data.csv                  # Windows EVTX converted security logs
│   ├── mac_failed_logins.csv          # Mac failed login history
│   ├── realtime_alerts.csv            # Live alerts generated by agents
│   └── virustotal_results.csv         # VirusTotal scan results
│
├── queries/                           # Custom analytical queries
└── reports/                           # Exported incident reports
    └── incident_report.pdf
```

---

## 🔐 Authentication & Credentials

### 1. 🖥️ SOC Dashboard Web UI Login
When accessing the dashboard in your web browser:
- **URL:** `http://localhost:8501`
- **Username:** `admin`
- **Password:** `soc123`
- *(Configured in [dashboard/auth.py](dashboard/auth.py))*

### 2. 🔑 Backend API Authentication (JWT)
- **POST Endpoint:** `http://127.0.0.1:8000/login`
- **Subject:** `socadmin`
- **Algorithm:** `HS256`

### 3. 🧪 Mac Terminal Demo Credentials
For running the standalone [api/mac_failed_login_monitor.py](api/mac_failed_login_monitor.py) demo:
- **Correct Password:** `demo123`
- *(Enter wrong password 2–3 times to simulate alert generation)*

---

## ⚙️ Prerequisites & Installation

### 1. Prerequisites
- **macOS** (for live macOS log stream and unified agent monitoring) or Linux/Windows (for dashboard, backend, and static datasets)
- **Python 3.10, 3.11, or 3.12**
- **Git**

### 2. Clone the Repository
```bash
git clone https://github.com/your-username/Threat-Intelligence-System.git
cd Threat-Intelligence-System
```

### 3. Create & Activate Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 🔑 Configuration (.env)

Create or verify the `.env` file in the root directory:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

> **Note:** Free API keys can be obtained from [AbuseIPDB](https://www.abuseipdb.com/) and [VirusTotal](https://www.virustotal.com/).

---

## 🚀 How to Run (Step-by-Step Guide)

For a complete end-to-end operational SOC environment, run the following components across separate terminal tabs (with your virtual environment activated):

### 🖥️ Terminal 1: Streamlit SOC Dashboard
Launches the web UI on port 8501:
```bash
streamlit run dashboard/app.py
```
*Open your browser and navigate to:* **`http://localhost:8501`** *(Login with `admin` / `soc123`)*

---

### 🛡️ Terminal 2: Real-Time Process Monitor Agent
Continuously monitors active host processes using `psutil` and logs suspicious security tools into `datasets/realtime_alerts.csv`:
```bash
python3 dashboard/agent/real_time_agent.py
```

---

### 🔐 Terminal 3: macOS Unified Log Monitor Agent
Streams live macOS system logs (`log stream`) to capture failed sudo attempts and authentication failures:
```bash
python3 dashboard/agent/mac_failed_password_monitor.py
```

---

### ⚙️ Terminal 4: FastAPI Backend API Server
Runs the REST API backend serving `/alerts` and `/login`:
```bash
uvicorn backend.api:app --reload --port 8000
```
*API Documentation available at:* **`http://127.0.0.1:8000/docs`**

---

### 🎲 Terminal 5 (Optional): Attack Simulator
Periodically injects synthetic high/medium/low severity threat events directly into the backend SQLite database:
```bash
python3 backend/attack_simulator.py
```

---

## 🧪 Testing & Simulating Threat Alerts

### 1. Test Process Detection
While `real_time_agent.py` is running (Terminal 2), trigger an alert using any security/networking utility:
```bash
# Option A: Run netcat
nc -zv 127.0.0.1 80

# Option B: Run the test process script
python3 malicious_test.py
```
**Expected Result:**
Terminal 2 prints `[ALERT] nc detected | PID: <pid> | Keyword: nc` and the event immediately shows up in the Dashboard under **🚨 Alerts** and **Real-Time Mac Process & System Alerts**.

### 2. Test Sudo / Failed Password Detection
While `mac_failed_password_monitor.py` is running (Terminal 3):
```bash
sudo ls
```
Enter an **incorrect password** 1–2 times.  
**Expected Result:**
Terminal 3 outputs `[ALERT] Failed sudo password detected`, writing the entry to `datasets/realtime_alerts.csv` and reflecting in the UI within 5 seconds.

### 3. Test Interactive Threat Intelligence Lookups
1. Scroll down to **"Live VirusTotal IP Lookup"** or **"IOC Search Panel"** in the Dashboard.
2. Enter any public IP address (e.g., `8.8.8.8` or `1.1.1.1`).
3. Click **Scan IP** to retrieve live reputation metrics directly from the VirusTotal API.

---

## 🌐 Threat Intelligence Enrichment Pipeline

The pipeline enriches offline endpoint logs with live AbuseIPDB intelligence:

```bash
# 1. Run AbuseIPDB log enrichment on raw endpoint logs:
python3 api/enrich_logs.py

# 2. Run VirusTotal indicator check:
python3 api/virustotal_lookup.py

# 3. Test single IP check via AbuseIPDB:
python3 api/threat_intel.py
```

- **Input:** `datasets/endpoint_risk_logs.csv`
- **Processing:** Extracts unique IP addresses, queries AbuseIPDB v2 API with rate-limiting safety.
- **Output:** Saves enriched dataset with ISP, Country, Abuse Score, and Tor status to `datasets/enriched_endpoint_logs.csv`.

---

## 🔌 Backend REST API Reference

The backend provides a lightweight REST API powered by **FastAPI**:

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Health check endpoint | No |
| `GET` | `/alerts` | Fetches all stored alerts from `alerts.db` | No |
| `POST` | `/login` | Generates a JWT access token for administrative actions | No |
| `GET` | `/docs` | Interactive Swagger UI API documentation | No |

### Example Request:
```bash
curl -X GET http://127.0.0.1:8000/alerts
```

### Example Response:
```json
{
  "alerts": [
    [
      "2026-08-18 11:40:00",
      "Suspicious Process Execution",
      "High",
      85,
      "Mac Real-Time Agent",
      "Detected suspicious keyword: nc"
    ]
  ]
}
```

---

## 🐳 Docker Deployment

You can build and deploy the SOC Dashboard using Docker:

### 1. Build the Docker Image
```bash
docker build -t threat-intelligence-system .
```

### 2. Run the Container
```bash
docker run -d -p 8501:8501 --name soc-dashboard threat-intelligence-system
```

### 3. Access Dashboard
Navigate to `http://localhost:8501` in your browser.

---

## ❓ Troubleshooting & FAQs

### Q1: `ModuleNotFoundError: No module named 'database'` when starting Uvicorn
**Fix:** Ensure you run `uvicorn` from the project root using `uvicorn backend.api:app --reload --port 8000`. All backend modules have dynamic `sys.path` resolution included.

### Q2: Terminal shows `[ALERT]`, but alerts are not visible in the frontend
**Fix:**
1. Ensure `datasets/realtime_alerts.csv` exists and has an 8-column header (`time,attack_type,process_name,pid,risk_score,risk_level,source,details`).
2. Refresh the dashboard (`R` in Streamlit).
3. Check the **🚨 Alerts** tab at the top or scroll down to the **"Real-Time Mac Process & System Alerts"** section.

### Q3: `Backend API error: HTTPConnectionPool... Connection refused` in Dashboard
**Fix:** Start the FastAPI backend server in a separate terminal:
```bash
uvicorn backend.api:app --reload --port 8000
```

### Q4: AbuseIPDB or VirusTotal API errors
**Fix:** Verify that valid API keys are placed in your `.env` file in the root directory:
```env
ABUSEIPDB_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
```

---

## 📄 License
This project is developed for educational, cybersecurity research, and Security Operations Center (SOC) demonstration purposes.
