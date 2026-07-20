<div align="center">

<img src="https://img.shields.io/badge/InsiderShield-Threat%20Detection-1F4E79?style=for-the-badge&logo=shield&logoColor=white" />

# 🛡️ InsiderShield
### Real-Time Insider Threat Detection Platform

*Kafka · Spark · Scikit-learn · Claude AI · Streamlit*

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io)
[![Scikit-learn](https://img.shields.io/badge/Scikit--learn-ML-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Claude AI](https://img.shields.io/badge/Claude-AI%20Narratives-8B5CF6?style=flat-square&logo=anthropic&logoColor=white)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)](LICENSE)

<br/>

> **Detects, scores, explains, and predicts insider threats in real time — across 1,200+ access events — using a 7-signal risk engine, machine learning, and AI-generated threat narratives.**

<br/>

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [How It Works](#-how-it-works) · [Screenshots](#-dashboard-preview) · [Tech Stack](#-tech-stack)

---

</div>

## 🚨 The Problem

Organizations generate millions of access events every day. Most are routine. But buried inside that volume are the events that matter — a user exporting data they have no reason to touch, a dormant account suddenly performing admin operations at 3 AM, or a low-privilege employee accessing restricted systems.

Traditional tools catch these too late, if at all. InsiderShield changes that.

---

## ✨ Features

| Module | What It Does |
|--------|-------------|
| **📊 Dashboard** | Live alert feed, risk score histogram, repeat-offender rankings, access heatmap, FP tracker |
| **🔍 Investigate** | Click-to-drill user dossier, anomaly signal breakdown, 30-day activity timeline |
| **🤖 AI Narrative** | Claude API generates a 3-sentence threat summary per alert — what happened, why it's suspicious, what to do |
| **🔮 Predictions** | 7-day risk trajectory (Logistic Regression), behavioral clustering (K-Means), recommendation engine |
| **⚡ Live Pipeline** | Real-time Kafka→Spark simulation with event feed, live metrics, and post-run severity report |
| **📄 PDF Export** | One-click downloadable threat report per alert |
| **✅ FP Management** | Mark false positives, escalate to CRITICAL, track resolution rate |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    INSIDERSHIELD PIPELINE                       │
│                                                                 │
│  CSV / Kafka Topic                                              │
│       │                                                         │
│       ▼                                                         │
│  ┌─────────────┐     ┌──────────────────┐    ┌──────────────┐  │
│  │  simulator  │────▶│  spark_processor │───▶│ alerts_output│  │
│  │  (Kafka sim)│     │  (Risk Engine)   │    │    .csv      │  │
│  └─────────────┘     └──────────────────┘    └──────┬───────┘  │
│                             │                        │          │
│                    user_profiles.csv                 │          │
│                    (Redis in prod)                   ▼          │
│                                              ┌──────────────┐  │
│                                              │  Streamlit   │  │
│                                              │  Dashboard   │  │
│                                              └──────┬───────┘  │
│                                                     │          │
│                                              ┌──────▼───────┐  │
│                                              │  Claude API  │  │
│                                              │ (Narratives) │  │
│                                              └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Hackathon vs Production

| Layer | This Repo | Production Equivalent |
|-------|-----------|----------------------|
| Event Ingestion | `simulator.py` reads CSV | Apache Kafka (12 partitions, 100k msg/sec) |
| Stream Processing | Python loop in `spark_processor.py` | Apache Spark Streaming (20 worker nodes) |
| User Profile Lookup | In-memory dictionary | Redis Cache (sub-millisecond) |
| Storage | `alerts_output.csv` | PostgreSQL + S3 Parquet |
| Full-text Search | — | Elasticsearch |
| Dashboard | Streamlit | React + FastAPI |

**Production headroom: 10,000 events/sec on 20 Spark nodes — 200× above the 50 events/sec peak load at 1M events/day.**

---

## ⚡ Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/VishalBasapure/Insider-Threat-Detection.git
cd Insider-Threat-Detection
pip install -r requirements.txt
```

### 2. Set Your Anthropic API Key

The AI narrative feature uses Claude. Get a free key at [console.anthropic.com](https://console.anthropic.com).

```bash
# Option A: environment variable (recommended)
export ANTHROPIC_API_KEY=sk-ant-...

# Option B: Streamlit secrets
mkdir -p .streamlit
echo '[secrets]\nANTHROPIC_API_KEY = "sk-ant-..."' > .streamlit/secrets.toml
```

> **Note:** The app works fully without an API key — only the AI Narrative button in the Investigate tab requires it.

### 3. Generate Alert Data

```bash
python pipeline.py
# Outputs: alerts_output.csv (1,200 scored events)
```

### 4. Run the Dashboard

```bash
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501)

---

## 🧠 How It Works

### 7-Signal Risk Engine

Every event is scored 0–100 using seven independent signals:

```python
score = 0

# Signal 1 — Off-hours access
if time_classification in ['night', 'unusual_hours']:
    score += 20

# Signal 2 — Resource sensitivity  
sensitivity_score = {'low': 0, 'medium': 10, 'high': 25, 'restricted': 35}
score += sensitivity_score[resource_sensitivity]

# Signal 3 — Action risk level
action_score = {'export_data': 25, 'admin_operation': 20, 'api_call': 8, ...}
score += action_score[action]

# Signal 4 — Unapproved resource access
if resource not in user_approved_systems:
    score += 20

# Signal 5 — Privilege mismatch
if privilege == 'user' and action == 'admin_operation':
    score += 30

# Signal 6 — Failed access attempt
if status == 'failure':
    score += 15

# Signal 7 — Stale account activity  
if days_inactive > 30:
    score += 20

# False positive suppression
if privilege == 'admin' and resource in approved_systems:
    score -= 25

score = min(score, 100)
```

| Score Range | Severity | Action |
|------------|----------|--------|
| 85 – 100 | 🔴 CRITICAL | Immediate suspension + SOC escalation |
| 65 – 84 | 🟠 HIGH | Investigate within 1 hour |
| 40 – 64 | 🟡 MEDIUM | Review within 24 hours |
| 0 – 39 | 🟢 LOW | Routine monthly review |

### ML Layer

**Logistic Regression** (predictive risk trajectory)
- Features: action type, resource, time classification, privilege, sensitivity, days inactive
- Label-encoded with `LabelEncoder`, scaled with `StandardScaler`
- Predicts 7-day forward risk per user

**K-Means Clustering** (behavioral profiling)
- Groups users by: avg score, night access ratio, sensitivity avg, admin ratio, export ratio, failure ratio
- 3 clusters: Standard Access · High-Risk Behavior · Off-Hours/Elevated

### AI Narrative (Claude API)

For each alert, the investigation panel calls `claude-sonnet-4-6` with a prompt built from the user's profile, event context, and triggered signals. The response is always three sentences:

1. What specifically triggered this alert
2. Why this pattern is suspicious given the user's profile
3. Recommended action for the security team

---

## 📁 Project Structure

```
Insider-Threat-Detection/
├── app.py                  # Streamlit dashboard (4 tabs)
├── pipeline.py             # Wires simulator → processor → output
├── simulator.py            # Kafka replacement — streams CSV as JSON events
├── spark_processor.py      # Spark replacement — scores each event
├── data_access_logs.csv    # 1,200 raw access events
├── user_profiles.csv       # 100 user profiles with role/privilege/systems
├── alerts_output.csv       # Pre-scored events (generated by pipeline.py)
├── SCALING.md              # Production architecture breakdown
└── requirements.txt
```

---

## 📦 Requirements

```txt
streamlit
pandas
plotly
scikit-learn
fpdf2
requests
numpy
```

Install all with:
```bash
pip install -r requirements.txt
```

---

## 🖥️ Dashboard Preview

### 📊 Main Dashboard
- **KPI Row:** Total Events · Critical Alerts · Users Flagged · False Positives
- **Alert Feed:** Top 10 CRITICAL/HIGH events, color-coded by severity
- **Risk Histogram:** Distribution across all 1,200 events by score band
- **Repeat Offenders:** Horizontal bar chart of cumulative risk by user
- **Access Heatmap:** Alert clusters by hour of day × day of week
- **Threshold Chart:** How alert count shifts as scoring cutoff changes

### 🔍 Investigate Tab
- Select any alert → user dossier card opens instantly
- Anomaly signal breakdown with weighted progress bars
- 30-day scatter timeline: normal activity vs risk spikes
- AI narrative generation on demand
- Actions: Mark FP · Escalate · Export PDF

### 🔮 Predictions Tab
- 7-day risk trajectory per top-12 users (line chart with threshold markers)
- Behavioral cluster scatter (avg score vs night-access ratio)
- Rule optimization recommendations based on FP patterns

### ⚡ Live Pipeline Tab
- Configurable speed (1–50 events/sec) and event count
- Live scrolling terminal feed of CRITICAL/HIGH events
- Real-time metrics: Processed · Alerts · Critical · Rate
- Post-simulation report: severity breakdown, top offenders, remediation playbook

---

## 🔬 Tech Stack

| Category | Tools |
|----------|-------|
| **Language** | Python 3.10+ |
| **Dashboard** | Streamlit, Plotly |
| **ML / Data** | Scikit-learn, Pandas, NumPy |
| **AI** | Anthropic Claude API (`claude-sonnet-4-6`) |
| **PDF Export** | fpdf2 |
| **Architecture (simulated)** | Apache Kafka, Apache Spark Streaming |
| **Architecture (production)** | Redis, PostgreSQL, S3, Elasticsearch |

---

## 📈 Performance

| Metric | Value |
|--------|-------|
| Events processed | 1,200 per demo run |
| Pipeline throughput (demo) | Up to 50 events/sec |
| Scoring latency | < 1ms per event |
| Production target | 1M+ events/day · 10,000 events/sec |
| ML training time | < 2 seconds on 1,200 events |
| Dashboard load time | < 3 seconds |

---

## 🗺️ Roadmap

- [ ] Replace CSV simulator with live Kafka consumer
- [ ] Deploy Spark job to AWS EMR / Databricks
- [ ] Add LSTM-based anomaly detection for sequence-aware scoring
- [ ] Network traffic signals (volume, lateral movement)
- [ ] Slack / PagerDuty webhook integration for CRITICAL alerts
- [ ] Role-based access for analyst vs manager dashboard views
- [ ] Auto-learn signal weights from labeled incident feedback

---

## 👤 Author

**Vishal Basapure**  
MCA · PES University, Bengaluru  
AI/ML · Full Stack · Data Science

[![GitHub](https://img.shields.io/badge/GitHub-VishalBasapure-181717?style=flat-square&logo=github)](https://github.com/VishalBasapure)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built for the **CIDECODE Hackathon 2026** · CID Karnataka / CCITR / PES University

*If this helped you, drop a ⭐ — it means a lot.*

</div>