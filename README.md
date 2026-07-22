<div align="center">

# 🛡️ InsiderShield
### Real-Time Insider Threat Detection Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io)
[![Gemini AI](https://img.shields.io/badge/Gemini-AI%20Analysis-4285F4?style=flat-square&logo=google&logoColor=white)](https://ai.google.dev)
[![Scikit-learn](https://img.shields.io/badge/Scikit--learn-ML-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)](LICENSE)

<br/>

> **Detects, scores, explains, and predicts insider threats in real time — across 1,200+ access log events — using a 7-signal risk engine, machine learning, and Gemini AI-generated threat narratives.**

<br/>

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [How It Works](#-how-it-works) · [Project Structure](#-project-structure) · [Tech Stack](#-tech-stack)

---

</div>

## 🚨 The Problem

Most organizations only discover insider threats after the damage is done — because they have the data, but not the tooling to process it in real time with context. A login at 3 AM looks fine in a spreadsheet. In InsiderShield, it's flagged within milliseconds.

---

## ✨ Features

| Module | What It Does |
|--------|-------------|
| **📊 Dashboard** | Live alert feed, risk histogram, repeat-offender bar chart, access heatmap, FP tracker, threshold sensitivity chart |
| **🔍 Investigate** | Click any alert → user dossier card, signal breakdown with progress bars, 30-day activity timeline |
| **🤖 AI Narrative** | Gemini generates a plain-English threat summary per alert — what triggered it, why it's suspicious, what to do |
| **🔮 Predictions** | 7-day risk trajectory (Logistic Regression) + behavioral clustering (K-Means) + recommendation engine |
| **⚡ Live Pipeline** | Real-time Kafka→Spark simulation — watch events stream in, see metrics update live, get a full AI triage report after |
| **📄 PDF Export** | One-click downloadable report per alert from the Investigate tab |
| **✅ FP Management** | Mark false positives, escalate to CRITICAL, track the resolution count on the dashboard |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   INSIDERSHIELD PIPELINE                     │
│                                                              │
│   data_access_logs.csv  ←→  (Kafka topic in production)     │
│              │                                               │
│              ▼                                               │
│       simulator.py          ← Kafka producer sim            │
│       (streams JSON events one-by-one)                       │
│              │                                               │
│              ▼                                               │
│      spark_processor.py     ← Spark Streaming sim           │
│      (score_event per event + user profile lookup)           │
│              │                                               │
│    user_profiles.csv        ← Redis cache in production      │
│              │                                               │
│              ▼                                               │
│       alerts_output.csv     ← PostgreSQL in production       │
│              │                                               │
│              ▼                                               │
│         app.py              ← Streamlit Dashboard            │
│              │                                               │
│              ▼                                               │
│       Gemini API            ← AI threat narratives           │
└──────────────────────────────────────────────────────────────┘
```

### Hackathon vs Production

| Layer | This Repo | Production |
|-------|-----------|------------|
| Event ingestion | `simulator.py` reads CSV row-by-row | Apache Kafka — 12 partitions, 100k msg/sec |
| Stream processing | Python loop in `spark_processor.py` | Apache Spark Streaming — 20 worker nodes |
| User profile lookup | In-memory Python dict | Redis — sub-millisecond |
| Alert storage | `alerts_output.csv` | PostgreSQL + S3 Parquet |
| Dashboard | Streamlit | React + FastAPI |
| AI analysis | Google Gemini API | Google Gemini API |

**Headroom: 10,000 events/sec on Spark — 200× above the 50 events/sec peak at 1M events/day.**

---

## ⚡ Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/VishalBasapure/Insider-Threat-Detection.git
cd Insider-Threat-Detection
pip install -r requirements.txt
```

### 2. Add Your Gemini API Key

Get a free key at [aistudio.google.com](https://aistudio.google.com/app/apikey).

Create `.streamlit/secrets.toml`:

```toml
GEMINI_API_KEY = "your-key-here"
```

> **Without a key:** the app runs fully — only the AI narrative button and post-pipeline triage report won't generate text.

### 3. Generate Alert Data

```bash
python pipeline.py
# Creates alerts_output.csv — 1,200 pre-scored events
```

### 4. Launch the Dashboard

```bash
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501)

---

## 🧠 How It Works

### 7-Signal Risk Engine (`spark_processor.py`)

Every access event gets scored 0–100 using seven independent signals:

```python
# Signal 1 — Off-hours access
if time_classification in ['night', 'unusual_hours']:
    score += 20

# Signal 2 — Resource sensitivity
sensitivity_score = {'low': 0, 'medium': 10, 'high': 25, 'restricted': 35}
score += sensitivity_score[resource_sensitivity]

# Signal 3 — Action risk level
action_score = {'export_data': 25, 'admin_operation': 20, 'api_call': 8, 'sql_query': 5}
score += action_score.get(action, 5)

# Signal 4 — Unapproved resource
if resource not in user_approved_systems:
    score += 20

# Signal 5 — Privilege mismatch
if privilege == 'user' and action == 'admin_operation':
    score += 30

# Signal 6 — Failed access attempt
if status == 'failure':
    score += 15

# Signal 7 — Stale account (inactive > 30 days)
if days_inactive > 30:
    score += 20

# False positive suppression
if privilege == 'admin' and resource in approved_systems:
    score -= 25

score = min(score, 100)
```

| Score | Severity | Response |
|-------|----------|----------|
| 85–100 | 🔴 CRITICAL | Immediate account suspension + SOC escalation |
| 65–84 | 🟠 HIGH | Investigate within 1 hour |
| 40–64 | 🟡 MEDIUM | Review within 24 hours |
| 0–39 | 🟢 LOW | Routine monthly review |

---

### ML Layer

**Logistic Regression — 7-day risk trajectory**
- Features per event: action type, resource, time classification, privilege level, sensitivity, days inactive
- Preprocessing: `LabelEncoder` for categoricals, `StandardScaler` for normalization
- Target: binary — whether the event scores ≥ 65 (HIGH or above)
- Output: projected risk curve per user for the next 7 days

**K-Means Clustering — behavioral profiling**
- Aggregates per user: avg score, night access ratio, sensitivity avg, admin ratio, export ratio, failure ratio
- 3 clusters: `Standard Access` · `High-Risk Behavior` · `Off-Hours / Elevated`
- Shown as a scatter plot in the Predictions tab

---

### AI Triage (Gemini API)

Two places in the app call Gemini:

1. **Investigate tab** — On-demand per alert. Click "Generate AI Analysis" to get a structured breakdown: what triggered it, why it's suspicious given the user's profile, and a recommended action.

2. **Live Pipeline — Post-run triage report** — After the pipeline finishes, every CRITICAL alert is automatically sent to Gemini for analysis. Each one expands into a full dossier: signal breakdown bars, AI assessment sections, and two quick-action cards (Disable in AD · Pull 72-hour logs).

---

## 📁 Project Structure

```
Insider-Threat-Detection/
│
├── app.py                   # Main Streamlit dashboard — 4 tabs, all UI
├── pipeline.py              # Wires simulator → spark_processor → CSV output
├── simulator.py             # Kafka simulator — streams CSV as JSON events
├── spark_processor.py       # Spark simulator — score_event() function
│
├── data_access_logs.csv     # 1,200 raw access log events
├── user_profiles.csv        # 100 user profiles (role, privilege, systems, inactive days)
├── alerts_output.csv        # Pre-scored output — generated by pipeline.py
│
├── SCALING.md               # Production architecture breakdown
├── requirements.txt
└── .streamlit/
    └── secrets.toml         # Your GEMINI_API_KEY goes here (not committed)
```

---

## 📦 Requirements

```txt
streamlit
pandas
plotly
scikit-learn
fpdf2
numpy
google-genai
```

```bash
pip install -r requirements.txt
```

---

## 🖥️ What Each Tab Does

### 📊 Dashboard
The first thing you see. Answers: *How bad is it right now?*
- 4 KPI cards: Total Events · Critical Alerts · Users Flagged · False Positives  
- Color-coded alert feed (top 10 CRITICAL/HIGH, sorted by score)
- Risk score histogram across all 1,200 events
- Top 10 repeat offenders by cumulative risk
- Hour × Day-of-week access heatmap (shows when attacks cluster)
- Severity donut + false positive tracker
- Threshold sensitivity chart (how alert count changes at each cutoff)

### 🔍 Investigate
Click any alert row → full investigation panel opens. Answers: *Why was this flagged?*
- User dossier: name, role, department, privilege, hire date, inactive days
- Anomaly signal breakdown with weighted progress bars showing each signal's contribution
- 30-day scatter timeline: normal events (green) vs risk spikes (red)
- "Generate AI Analysis" button → Gemini writes a 3-section threat assessment
- Actions: Mark as False Positive · Escalate to CRITICAL · Export PDF report

### 🔮 Predictions
Forward-looking view. Answers: *Who is trending toward a breach?*
- 7-day risk trajectory chart for top-12 high-risk users (with CRITICAL/HIGH threshold lines)
- K-Means cluster scatter: avg score vs night-access ratio, colored by cluster
- Cluster summary table (3 profiles: Standard / High-Risk / Off-Hours)
- AI recommendation cards: rule weight adjustments, MFA policy, stale account cleanup

### ⚡ Live Pipeline
The "wow" tab. Shows the system actually working. Answers: *Can I see it process events live?*
- Speed slider (1–50 events/sec) and event count slider
- Live scrolling terminal feed — CRITICAL events in red, HIGH in orange
- Four real-time metrics updating every event: Processed · Alerts · Critical · Rate
- After completion: full AI Triage Report for every CRITICAL alert, each in an expander with signal bars, Gemini analysis, and quick-action cards

---

## 📈 Performance

| Metric | Value |
|--------|-------|
| Events in demo | 1,200 |
| Max pipeline speed | 50 events/sec |
| Scoring latency | < 1ms per event |
| ML training time | < 2 seconds |
| Production target | 1M+ events/day · 10,000 events/sec on Spark |

---

## 🗺️ Roadmap

- [ ] Replace CSV simulator with live Kafka consumer
- [ ] Spark job deployment on AWS EMR / Databricks
- [ ] LSTM sequence model for detecting multi-step attack chains
- [ ] Slack / PagerDuty webhook on CRITICAL alerts
- [ ] Network volume signals (data exfiltration detection)
- [ ] Role-based access: analyst view vs SOC manager view

---

## 👤 Author

**Vishal Basapure**  
MCA · PES University, Bengaluru  
AI/ML · Full Stack · Cybersecurity

[![GitHub](https://img.shields.io/badge/GitHub-VishalBasapure-181717?style=flat-square&logo=github)](https://github.com/VishalBasapure)

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Built for **Societal General Hackathon 2026** ·PES University

*If this project helped you, drop a ⭐*

</div>