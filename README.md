# 🛡️ AI Threat Hunter

> **Two-layer AWS CloudTrail anomaly detection engine** — combines deterministic IOC rules with an unsupervised Isolation Forest ML model to surface threats that signature-only tools miss.

---

## What It Does

AI Threat Hunter ingests AWS CloudTrail logs and runs every event through two independent detection engines:

| Layer | Engine | What it catches |
|-------|--------|-----------------|
| 1 | **Rule Engine** | Known TOR exit nodes, high-risk API calls (DeleteTrail, AttachUserPolicy, CreateUser), sensitive bucket exfiltration, off-hours activity, privilege escalation chains |
| 2 | **ML Engine** (Isolation Forest) | Statistically anomalous events that don't match any rule — unknown unknowns |

Alerts from both engines are merged, deduplicated, and ranked by severity. Events flagged by **both** engines are automatically escalated.

---

## Sample Output

```
════════════════════════════════════════════════════════════════════════
  AI THREAT HUNTER  —  Detection Report
  Generated : 2025-06-10 17:30:25 UTC
  Total Alerts : 7
  🔴 CRITICAL:2  🟠 HIGH:5
════════════════════════════════════════════════════════════════════════

  [01] 🔴 CRITICAL  —  AttachUserPolicy
       Time    : 2025-06-10T10:35:00Z
       User    : svc-backup
       Source  : 185.220.101.47
       Tactic  : privilege_escalation
       Engine  : rule + ml
       ML Conf : 100%  (score: -0.7938)
       Findings:
         • Source IP 185.220.101.47 is a known TOR exit node
         • AdministratorAccess policy attached — CRITICAL privilege escalation
         • Isolation Forest anomaly score: -0.7938 (confidence: 100%)

  [02] 🔴 CRITICAL  —  GetObject
       Time    : 2025-06-10T12:35:00Z
       User    : analyst-01
       Source  : 94.102.49.193
       Tactic  : exfiltration
       Engine  : rule + ml
       ML Conf : 100%
       Findings:
         • Source IP 94.102.49.193 is a known TOR exit node
         • Sensitive bucket 'prod-pii-data' accessed from TOR exit node

  MITRE ATT&CK Tactic Breakdown
  privilege_escalation           █ 1
  exfiltration                   █ 1
  persistence                    █ 1
  defense_evasion                █ 1
  initial_access                 █ 1
  anomaly_detected               ██ 2
════════════════════════════════════════════════════════════════════════
```

---

## Architecture

```
CloudTrail Logs (JSON)
        │
        ▼
┌───────────────────────────────────────┐
│           Feature Extraction          │
│  (event source, hour, TOR flag,       │
│   API risk score, bucket sensitivity) │
└────────────┬──────────────────────────┘
             │
    ┌────────┴────────┐
    │                 │
    ▼                 ▼
┌──────────┐   ┌──────────────────┐
│  Rule    │   │  Isolation Forest │
│  Engine  │   │  ML Engine        │
│  (fast)  │   │  (unsupervised)   │
└────┬─────┘   └────────┬─────────┘
     │                  │
     └────────┬──────────┘
              ▼
    ┌──────────────────┐
    │  Merge + Dedup   │
    │  Severity Rank   │
    └────────┬─────────┘
             ▼
    ┌──────────────────┐
    │  Threat Report   │
    │  (Terminal + JSON)│
    └──────────────────┘
```

---

## Detection Rules

| Rule | Severity | MITRE Tactic |
|------|----------|--------------|
| Source IP matches TOR exit node list | HIGH | Initial Access |
| `DeleteTrail` or `StopLogging` called | CRITICAL | Defense Evasion |
| `AttachUserPolicy` with AdministratorAccess | CRITICAL | Privilege Escalation |
| `CreateUser` followed by policy attachment | CRITICAL | Persistence |
| `GetObject` on sensitive bucket from TOR IP | CRITICAL | Exfiltration |
| `CreateAccessKey` or `PutUserPolicy` | HIGH | Credential Access |
| API calls outside business hours (07:00–19:00 UTC) | LOW | Anomalous Behavior |
| Isolation Forest outlier score | MEDIUM / HIGH | Anomaly Detected |

---

## Project Structure

```
ai-threat-hunter/
├── src/
│   ├── detector.py        # Core detection engine (rules + ML)
│   └── report.py          # CLI report renderer + JSON export
├── data/
│   ├── generate_logs.py   # Synthetic CloudTrail log generator
│   └── cloudtrail_sample.json  # Generated after running above
├── output/
│   └── threat_report.json # Generated after running report.py
├── tests/
│   └── test_detector.py   # 9 unit tests (pytest)
├── requirements.txt
└── README.md
```

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/YOUR_USERNAME/ai-threat-hunter.git
cd ai-threat-hunter
pip install -r requirements.txt

# 2. Generate synthetic CloudTrail logs (305 events, 5 injected anomalies)
python data/generate_logs.py

# 3. Run detection + view report
python src/report.py

# 4. Run tests
python -m pytest tests/ -v
```

### Use Your Own Logs

```bash
python src/report.py --logs /path/to/your/cloudtrail.json
```

CloudTrail logs can be exported from the AWS Console or downloaded via:
```bash
aws cloudtrail lookup-events --output json > my_logs.json
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.11+ |
| ML Model | Scikit-learn `IsolationForest` |
| Numerics | NumPy |
| Testing | Pytest (9 tests) |
| Log Format | AWS CloudTrail JSON |
| Threat Intel | TOR exit node IOC list |
| Framework | MITRE ATT&CK |

---

## Key Design Decisions

**Why Isolation Forest?**
Isolation Forest is well-suited for security anomaly detection because it works *unsupervised* — it doesn't need labeled attack data (which is scarce and rapidly outdated). It learns the shape of normal, then flags deviations. It's also fast (O(n log n)), interpretable via anomaly scores, and handles high-dimensional tabular data well.

**Why two layers?**
Rules catch known-bad patterns instantly and with zero false positives on well-defined IOCs (e.g., TOR exit nodes). ML catches *novel* patterns the rules don't cover. Together they significantly improve recall without sacrificing precision on known threats.

**Why synthetic logs?**
Real CloudTrail logs contain sensitive infrastructure details. The synthetic generator produces statistically realistic baseline traffic with injected attack scenarios, allowing safe public sharing and reproducible testing.

---

## Roadmap

- [ ] Slack webhook integration for real-time alerts
- [ ] LSTM sequence model for temporal attack chain detection  
- [ ] Live AWS CloudTrail stream ingestion via Kinesis
- [ ] Dashboard UI (Streamlit)
- [ ] Additional IOC feeds (abuse.ch, AlienVault OTX)

---

## Author

**Saicharan Keerti** — Cybersecurity Engineer  
[LinkedIn](https://linkedin.com/in/s-charan) · [Email](mailto:saicharankeerti@gmail.com)

> *Built to demonstrate hands-on expertise in cloud security, threat detection engineering, and applied ML for cybersecurity.*
