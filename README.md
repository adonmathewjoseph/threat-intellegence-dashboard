# ⚡ SPECTRE // Cyber Threat Intelligence Platform

An open-source, tactical Threat Intelligence Dashboard (TIP) engineered for real-time aggregation of Indicators of Compromise (IOCs), Command and Control (C2) botnet tracking, vulnerability intelligence, and automated indicator triage.

Designed and optimized natively for **macOS Apple Silicon (ARM64)** and cross-platform Unix environments.

---

## 🚀 Features

- **Automated Multi-Feed Ingestion:**
  - **Abuse.ch Feodo Tracker:** Real-time ingestion of active Command and Control (C2) botnet IPs (QakBot, Emotet, Dridex).
  - **URLhaus:** Actively weaponized malware payload distribution URLs.
  - **CISA KEV Catalog:** Real-time catalog of Known Exploited Vulnerabilities and active zero-days.
- **Geographic Threat Mapping:** Real-time GeoIP resolution plotting threat origins and C2 host nodes onto a dark-mode interactive global projection.
- **Relational Normalized Schema:** SQLite + SQLAlchemy 2.0 ORM pipeline with deduplication and confidence score weighting.
- **Hybrid Forensics Search:** Local indexed indicator lookup paired with an external live API fallback directly to URLhaus cloud intelligence.
- **Modern Cyber SOC UI:** Built with Streamlit, Plotly, custom glassmorphic styling, and native JetBrains Mono / Plus Jakarta typography.

---

## 🛠️ Architecture

[ Threat Feeds: Feodo / URLhaus / CISA KEV ]
│
▼
[ ingest.py Engine ]
(Normalization, GeoIP Resolution, Deduplication)
│
▼
[ threat_intel.db (SQLite) ]
├── iocs (value, type, threat, confidence, country, coords)
└── vulnerabilities (cve_id, vendor, product, date)
│
▼
[ app.py (Streamlit) ]
(Telemetry Cards | Global Vector Map | IOC Explorer | Triage Search)

---

## 📦 Tech Stack

- **Frontend:** Streamlit & Plotly
- **Backend / Pipeline:** Python 3.11+, Requests, Pydantic
- **ORM / Database:** SQLAlchemy 2.0, SQLite
- **Styling:** Custom Glassmorphic Dark SOC CSS + Theme Configuration

---

## ⚡ Quick Start

### 1. Prerequisites
- macOS (Apple Silicon M1/M2/M3 native support) or Linux
- Python 3.10+
- Git

### 2. Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/threat-intel-dashboard.git](https://github.com/YOUR_USERNAME/threat-intel-dashboard.git)
cd threat-intel-dashboard

3. Set Up Virtual Environment
Bash
python3 -m venv venv
source venv/bin/activate

4. Install Dependencies
Bash
pip install --upgrade pip
pip install -r requirements.txt

5. Ingest Threat Intelligence Feeds
Initialize the SQLite schema and ingest initial indicators:

Bash
python3 ingest.py

6. Launch the Dashboard
Bash
streamlit run app.py



📁 Project Structure
Plaintext
├── .streamlit/
│   └── config.toml         # Custom dark theme configuration
├── models.py               # SQLAlchemy schema definitions (IOC & Vulnerability models)
├── ingest.py               # Multi-source threat feed ingestion and GeoIP enrichment
├── app.py                  # Main Streamlit web dashboard application
├── requirements.txt        # Pinned ARM64-compatible dependencies
├── .gitignore              # Ignores database files, venv, and cache
└── README.md               # Project documentation

🔒 Defanging Notice
Observables presented and logged across this tool are treated as active threats. URLs and domains should always be defanged (e.g., hxxp://domain[.]com) during incident response reports and documentation to prevent accidental payload execution.

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
