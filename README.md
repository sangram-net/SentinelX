# SentinelX

### Local Smart Log Sentinel

> **Turn logs into insights. Detect threats. Stay ahead.**

SentinelX is a lightweight local security log analysis and threat detection dashboard that transforms raw authentication and web logs into understandable security incidents.

Instead of manually searching through large amounts of log data, SentinelX parses events, detects suspicious patterns, correlates related activity, explains why something was flagged, and presents the results through a security-focused dashboard.

---

## 🛡️ Problem

Security logs contain valuable evidence, but raw log files are difficult to interpret quickly.

For cybersecurity students, developers, small teams, and local security labs, deploying a full enterprise SIEM can be unnecessary or overly complex.

This creates a simple problem:

> **How can raw security logs be converted into understandable, actionable incidents without requiring a full SIEM platform?**

SentinelX addresses this problem with a lightweight local analysis workflow.

---

## 💡 Solution

SentinelX takes a local `.log` or `.txt` file and processes it through a security analysis pipeline:

```text
Raw Logs
   ↓
Log Ingestion
   ↓
Parser & Normalizer
   ↓
Detection Engine
   ↓
Incident Correlation
   ↓
Severity & Evidence
   ↓
Attack Story
   ↓
Security Dashboard

The result is not just a list of suspicious log lines.
SentinelX attempts to answer:
- What happened?
- Where did it come from?
- What type of threat is it?
- Why was it detected?
- How severe is it?
- Which events are related?
- What should an analyst investigate next?
🚨 Key Features
1. Local Log Analysis
Upload a local security log file directly through the dashboard.
Supported input:
.log
.txt

The application processes the file locally through the SentinelX backend.
2. Security Event Parsing
SentinelX converts raw log lines into structured security events.
Example:
Failed password for admin from 192.168.1.50

can become:
Event Type: ssh_failed_login
User: admin
Source: 192.168.1.50

This makes raw telemetry easier to analyze.
3. Threat Detection
The current detection engine identifies several suspicious patterns:
SSH Brute Force
Detects repeated failed authentication attempts from a source.
Example:
Failed password for admin from 192.168.1.50
Failed password for root from 192.168.1.50
Failed password for test from 192.168.1.50

Result:
SSH Brute Force
Severity: HIGH

Password Spraying
Detects authentication failures where multiple accounts are targeted by the same source.
Example:
admin
root
test

from the same source:
192.168.1.50

Result:
Password Spraying
Severity: HIGH

SQL Injection Attempt
Detects suspicious SQL-related payloads inside web requests.
Example:
GET /login?id=' OR 1=1 -- from 10.0.0.5

Result:
SQL Injection Attempt
Severity: HIGH

Web Scanning
Detects repeated requests to multiple paths from the same source.
Example:
GET /admin
GET /wp-admin
GET /phpmyadmin
GET /backup
GET /config

Result:
Web Scanning
Severity: MEDIUM

🔎 Explainable Detection
SentinelX does not simply display:
THREAT DETECTED

For each detected incident, the dashboard provides:
Evidence
The relevant log evidence behind the detection.
Why Detected
A human-readable explanation of the detection rule.
Attack Story
A short interpretation of how the observed events may relate to an attack pattern.
Recommended Response
A practical next step for investigation or containment.
Example:
SSH Brute Force

Evidence:
Failed password for admin from 192.168.1.50

Why Detected:
3 failed SSH login attempts from the same source
targeting multiple accounts.

Attack Story:
A single source generated repeated failed
authentication attempts, consistent with a
possible brute-force attack.

Recommended Response:
Investigate the source IP, review affected
accounts, enforce rate limiting, and temporarily
block the source if confirmed malicious.

🧠 Incident Correlation
One of SentinelX's main goals is to move beyond individual log lines.
Instead of treating every event independently, SentinelX groups related activity into incidents.
For example:
Failed Login
      ↓
Failed Login
      ↓
Failed Login
      ↓
Multiple Accounts Targeted
      ↓
SSH Brute Force
      ↓
Password Spraying

The dashboard presents this relationship as an Attack Story and Attack Timeline.
This gives the analyst context instead of isolated alerts.
📊 Security Dashboard
The dashboard provides an overview of the analyzed log file.
Current metrics include:
Total Events
Threats Detected
High Severity
Incidents

The interface also provides:
- Recent Incidents
- Evidence
- Detection explanations
- Attack Stories
- Recommended Responses
- Attack Timeline
- Attack Overview
- Analyzed Events
🏗️ Architecture
                    ┌──────────────────┐
                    │    Raw Log File  │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │  Log Ingestion   │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Parser /         │
                    │ Normalizer       │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Detection Engine │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Incident         │
                    │ Correlation      │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Severity &       │
                    │ Evidence         │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Attack Story     │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Security         │
                    │ Dashboard        │
                    └──────────────────┘

🧩 Project Structure
SentinelX/
│
├── api/
│   ├── detector.py
│   ├── main.py
│   └── parser.py
│
├── data/
│   └── logs/
│       ├── test.log
│       └── sqli.log
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── assets/
│   │   ├── App.css
│   │   ├── App.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
│
├── .gitignore
├── README.md
└── requirements.txt

⚙️ Technology Stack
Frontend
- React
- Vite
- JavaScript
- CSS
Backend
- Python
- FastAPI
- Uvicorn
Detection
- Python-based parsing
- Pattern and rule-based detection
- Incident correlation
- Severity classification
Data
- Local log files
- Structured JSON responses between frontend and backend
🚀 Running SentinelX Locally
Requirements
Install:
- Python 3
- Node.js
- npm
1. Clone the repository
git clone https://github.com/sangram-net/SentinelX.git

Enter the project:
cd SentinelX

2. Start the Backend
Create a Python virtual environment:
python3 -m venv .venv

Activate it:
source .venv/bin/activate

Install dependencies:
pip install -r requirements.txt

Start the API:
uvicorn api.main:app --reload

The backend will run at:
http://127.0.0.1:8000

API documentation:
http://127.0.0.1:8000/docs

Health endpoint:
http://127.0.0.1:8000/api/health

3. Start the Frontend
Open another terminal.
cd SentinelX/frontend

Install frontend dependencies:
npm install

Start the development server:
npm run dev

Open the local URL shown by Vite.
🧪 Testing SentinelX
Sample logs are included in:
data/logs/

Brute Force / Password Spraying Test
Upload:
data/logs/test.log

Expected detections include:
SSH Brute Force
Password Spraying

SQL Injection Test
Upload:
data/logs/sqli.log

Expected detection:
SQL Injection Attempt

📈 Example Analysis
For the included combined test data, SentinelX can produce results such as:
Total Events:      9
Threats Detected:  4
High Severity:     3
Incidents:         4

Detected incidents:
01  SSH Brute Force       HIGH
02  Password Spraying     HIGH
03  SQL Injection Attempt HIGH
04  Web Scanning          MEDIUM

These values are based on the included test scenario and are not intended to represent production detection accuracy.
🔐 Security & Responsible Use
SentinelX is designed for:
- Cybersecurity education
- Local security labs
- Developer environments
- Security experimentation
- Small-scale log analysis
- Defensive monitoring prototypes
SentinelX is not intended to replace a production SIEM, EDR, SOC platform, or professional incident-response system.
Detection results should be treated as investigation signals rather than definitive proof of malicious activity.
Users should only analyze logs and systems they are authorized to access.
⚠️ Current Limitations
SentinelX is an early-stage prototype.
Current limitations include:
- Rule-based detection
- Limited log formats
- Local file-based ingestion
- No distributed collection
- No authentication system
- No long-term event storage
- No production-scale alerting
- No automatic remediation
- Detection rules may produce false positives or false negatives
These limitations provide clear opportunities for future development.
🔮 Future Roadmap
Potential future improvements include:
Detection
- More authentication attack patterns
- Additional web attack signatures
- Malware-related indicators
- Suspicious process detection
- MITRE ATT&CK mapping
Log Sources
- Linux authentication logs
- Apache logs
- Nginx logs
- Windows Event Logs
- Cloud security logs
Platform
- Persistent incident database
- User authentication
- Role-based access control
- Real-time log streaming
- Alert notifications
- Exportable incident reports
Intelligence
- Detection confidence scoring
- Threat intelligence enrichment
- Behavioral anomaly detection
- Advanced event correlation
- Explainable machine-learning assistance
🎯 Why SentinelX?
Traditional log analysis often requires an analyst to manually connect individual events.
SentinelX focuses on making that process easier:
Raw Data
   ↓
Structured Events
   ↓
Detected Patterns
   ↓
Correlated Incidents
   ↓
Explainable Findings
   ↓
Actionable Investigation

The goal is simple:
Don't just show the logs. Tell the analyst what they might mean.

🏆 Hackathon
SentinelX was developed for:
WCC Launchpad 30
Track:
Open Innovation
The project focuses on building a practical cybersecurity tool that makes local security telemetry easier to understand and investigate.
🤖 AI Disclosure
AI-assisted development tools were used during the development process for activities including:
- Code assistance
- Debugging
- UI development
- Documentation
- Brainstorming
- Development guidance
The project architecture, implementation decisions, testing, integration, and final product were assembled and validated as part of the hackathon project.
📜 License
This project is released under the license included in the repository.
👨‍💻 Author
Sangram Ganguly
Cybersecurity Student & Developer
GitHub:
https://github.com/sangram-net
