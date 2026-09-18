# ckcSOC — 11-Layer Autonomous Cyber Incident Response Pipeline

> **Team CKC · Hack O Hire 2026 · Barclays SOC**

An AI-powered Security Operations Center pipeline that ingests heterogeneous security logs, normalizes them, detects threats via ML + LLM, generates automated playbooks, and provides a real-time dashboard — all orchestrated by a LangGraph state machine.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Running Services](#running-services)
  - [1. Generate Datasets](#1-generate-datasets)
  - [2. Start Infrastructure (Kafka + Elasticsearch)](#2-start-infrastructure-kafka--elasticsearch)
  - [3. Start Ollama (LLM Backend)](#3-start-ollama-llm-backend)
  - [4. Run the SOC Pipeline](#4-run-the-soc-pipeline)
  - [5. Start the API Gateway](#5-start-the-api-gateway)
  - [6. Start the Dashboard UI](#6-start-the-dashboard-ui)
  - [7. Start the Drift Monitor](#7-start-the-drift-monitor)
  - [8. Push Live Logs to Kafka](#8-push-live-logs-to-kafka)
- [Docker Compose (All-in-One)](#docker-compose-all-in-one)
- [Pipeline Layers](#pipeline-layers)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Environment Variables](#environment-variables)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                        ckcSOC Architecture                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Log Sources ──┐                                                     │
│  (JSON/CSV/    │    ┌──────────┐   ┌──────────┐   ┌──────────────┐  │
│   Syslog/KV/   ├───►│  Kafka   │──►│ Pipeline │──►│ Elasticsearch│  │
│   CEF/XML)     │    │ (broker) │   │(11-layer)│   │  (storage)   │  │
│                │    └──────────┘   └────┬─────┘   └──────────────┘  │
│  Dataset       │                        │                            │
│  Builders ─────┘                   ┌────▼─────┐                     │
│                                    │  Ollama  │                     │
│  ┌──────────┐   ┌──────────────┐   │  (LLM)   │                    │
│  │ React UI │◄──│ FastAPI GW   │   └──────────┘                    │
│  │(Vite+TS) │   │ (port 8000)  │                                    │
│  └──────────┘   └──────────────┘                                    │
│                                                                      │
│  ┌──────────────────┐                                                │
│  │  Drift Monitor   │  (continuous scoring distribution checks)     │
│  └──────────────────┘                                                │
└──────────────────────────────────────────────────────────────────────┘
```

---

## System Flow & Startup Modes

The system supports two primary modes:

```
┌─────────────────────────────────────────────────────────────┐
│  MODE 1: BATCH (Simplest)                                  │
│  ─────────────────────────────────────────────────────────  │
│  Dataset → Ollama → Pipeline (11 layers) → Results (JSON)  │
│  ✓ No Docker needed                                         │
│  ✓ Fastest to get started (~2 min)                         │
│  ✓ Best for: Learning, testing, CI/CD                      │
└─────────────────────────────────────────────────────────────┘

    ↓

┌─────────────────────────────────────────────────────────────┐
│  MODE 2: FULL SYSTEM (Production-Ready)                    │
│  ─────────────────────────────────────────────────────────  │
│  Olivama + Kafka + ES + Pipeline + API Gateway + Dashboard │
│  ✓ Real-time streaming                                      │
│  ✓ Web UI for visualization                                │
│  ✓ Best for: End-to-end testing, demonstrations            │
└─────────────────────────────────────────────────────────────┘
```

**Choose based on your needs:**
- **New to the project?** Start with **Mode 1 (Batch)** — 2 minutes, no Docker
- **Want to see the full UI?** Use **Mode 2 (Full System)** — 5 minutes with Docker

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| **Python** | 3.11+ | Pipeline, API, data generators |
| **Docker & Docker Compose** | 24+ | Kafka, Elasticsearch containers |
| **Node.js** | 18+ | Dashboard UI (Vite + React) |
| **Ollama** | latest | Local LLM for playbook generation |

### Install Python dependencies

```bash
# Create virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
# .venv\Scripts\activate     # Windows

# Install all dependencies
pip install -r requirements.txt
```

### Install Ollama

```bash
# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Pull required model
ollama pull llama3.2
```

### Install Node.js dependencies (for Dashboard UI)

```bash
cd ckcSOC-ui
npm install
cd ..
```

---

## Quick Start

Choose one of the two scenarios below:

### Scenario 1: Simple Batch Mode (No Docker, ~2 minutes)
Perfect for: Testing locally, no infrastructure overhead

```bash
# Terminal 1 — Start Ollama LLM server
ollama serve

# Terminal 2 — Run the pipeline end-to-end
python datasets/hetero_dataset_builder.py    # Generate 737 test events
python run_demo.py --no-plots                 # Run full 11-layer pipeline
```

**Output:** Results saved to `state/sentinel_memory.json`, `state/playbooks.json`, etc.

### Scenario 2: Full System (Docker + API + Dashboard, ~5 minutes)
Perfect for: Testing the complete real-time system with UI

```bash
# Terminal 1 — Start Ollama (GPU acceleration)
ollama serve

# Terminal 2 — Start Kafka + Elasticsearch
docker compose up -d kafka elasticsearch

# Terminal 3 — Start the API Gateway
uvicorn api.gateway_api:app --host 0.0.0.0 --port 8000 --reload

# Terminal 4 — Generate data and run pipeline
python datasets/hetero_dataset_builder.py
python run_demo.py --source kafka --no-plots

# Terminal 5 — Start the Dashboard UI
cd ckcSOC-ui && npm run dev
# Open browser to http://localhost:5173
```

---

## Running Services (Detailed)

### 1. Generate Datasets

There are two dataset builders available:

#### Standard Dataset (737 events, 4 formats)
```bash
python datasets/hetero_dataset_builder.py
```
Outputs:
- `datasets/hetero_events.mixed` — combined raw file
- `datasets/hetero/` — per-topic JSONL files

#### Competition Stress-Test Dataset (5,000+ events, 8 formats)
```bash
python datasets/hetero_dataset_builder_v2.py --events 5000 --chains 5
```
Outputs:
- `datasets/hetero_v2_events.mixed` — combined raw file (5,000+ events)
- `datasets/hetero_v2/` — per-topic JSONL files
- `datasets/hetero_v2/manifest.json` — test validation metadata

Options:
```bash
--events 50000         # Generate up to 50k events for stress testing
--dupe-ratio 0.10      # 10% exact duplicates (default: 5%)
--malformed-ratio 0.05 # 5% malformed lines (default: 2%)
--chains 5             # Number of attack chains to seed (max: 5)
```

---

### 2. Start Infrastructure (Kafka + Elasticsearch)

```bash
# Start Kafka broker + Elasticsearch in Docker
docker compose up -d kafka elasticsearch

# Verify they're healthy
docker compose ps
```

Wait for both services to become healthy (~30-60 seconds):
```bash
# Check Kafka
docker compose logs kafka | tail -5

# Check Elasticsearch
curl -s http://localhost:9200/_cluster/health | python -m json.tool
```

**Ports:**
| Service | Port | Health Check |
|---------|------|-------------|
| Kafka | `9092` | `kafka-topics.sh --list` |
| Elasticsearch | `9200` | `http://localhost:9200/_cluster/health` |

---

### 3. Start Ollama (LLM Backend)

Ollama runs **natively** (not in Docker) to leverage GPU acceleration:

```bash
# Terminal 1 — Start Ollama server
ollama serve
```

Verify it's running:
```bash
curl http://localhost:11434/api/tags
```

> **Note**: The pipeline uses `http://localhost:11434` by default. Inside Docker, it connects via `http://host.docker.internal:11434`.

---

### 4. Run the SOC Pipeline

#### Batch Mode (from file)
```bash
# Standard run (full 11-layer pipeline)
python run_demo.py --no-plots

# With custom dataset
python run_demo.py --dataset datasets/hetero_v2_events.mixed --no-plots

# Verbose mode (per-event logs, auto-caps at 1k events)
python run_demo.py --verbose --no-plots

# Limit events
python run_demo.py --limit 500 --no-plots
```

#### Streaming Mode (from Kafka)
```bash
# Requires Kafka to be running (Step 2)
python run_demo.py --source kafka --no-plots
```

#### Pipeline Output

All results are saved to the `state/` directory:
| File | Contents |
|------|----------|
| `state/sentinel_memory.json` | Stored incidents with verdicts |
| `state/playbooks.json` | Generated playbook recommendations |
| `state/audit_log.json` | Approval/rejection audit trail |
| `state/scoring_baseline.json` | Scoring distribution baseline |
| `state/drift_log.json` | Drift monitoring history |
| `state/fingerprints.json` | Event fingerprints for dedup |

---

### 5. Start the API Gateway

The FastAPI gateway serves pipeline data to the dashboard:

```bash
# Start the API server (port 8000)
uvicorn api.gateway_api:app --host 0.0.0.0 --port 8000 --reload
```

Verify:
```bash
curl http://localhost:8000/health
# {"status":"ok","service":"gateway"}
```

**API Endpoints:**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check |
| `/api/dashboard/summary` | GET | Pipeline status summary |
| `/api/dashboard/incidents` | GET | Sentinel memory incidents |
| `/api/dashboard/audit` | GET | Approval audit trail |
| `/api/dashboard/severity-distribution` | GET | Severity charts data |
| `/api/dashboard/drift` | GET | Drift monitoring log |
| `/api/dashboard/dataset-stats` | GET | Dataset statistics |
| `/api/dashboard/playbooks` | GET | Generated playbooks |
| `/ingest` | POST | Ingest events via API (auth required) |
| `/playbook/{cluster_id}` | GET | Get specific playbook (auth required) |

**Authentication tokens** (for protected endpoints):
```
reader-token-xxx    → reader role
approver-token-yyy  → approver role
admin-token-zzz     → admin role
```

---

### 6. Start the Dashboard UI

The React + TypeScript + Vite dashboard visualizes pipeline data:

```bash
cd ckcSOC-ui

# Install dependencies (first time only)
npm install

# Start development server (port 5173)
npm run dev
```

Open: **http://localhost:5173**

> The dashboard connects to the API gateway at `http://localhost:8000`.

#### Build for Production (Tauri Desktop App)
```bash
cd ckcSOC-ui
npm run build           # Build web assets
npm run tauri build      # Package as desktop app (optional)
```

---

### 7. Start the Drift Monitor

The drift monitor continuously compares live scoring distributions against the baseline:

```bash
# Continuous mode (runs every 5 minutes)
python -m pipeline.drift_monitor

# Single check
python -m pipeline.drift_monitor --once
```

> The drift monitor uses PSI (Population Stability Index) and KS statistics to detect model drift. Thresholds: PSI > 0.2 or KS > 0.15 triggers an alert.

---

### 8. Push Live Logs to Kafka

Stream generated heterogeneous logs into Kafka for the pipeline to consume in real-time:

#### Using the root-level pusher
```bash
# Push all hetero logs to Kafka (requires Kafka running)
python push_hetero_logs.py

# Control rate and filter by topic
python push_hetero_logs.py --rate 500 --topic auth_events
```

#### Using the kafka module pusher
```bash
python -m kafka.hetero_pusher --rate 200
python -m kafka.hetero_pusher --rate 50 --topic auth_events
```

---

## Docker Compose (All-in-One)

Run everything with Docker Compose (except Ollama, which must run natively for GPU):

```bash
# Terminal 1 — Start Ollama natively
ollama serve

# Terminal 2 — Start all services
docker compose up -d                        # Infrastructure (Kafka + ES + API + Drift Monitor)
docker compose --profile run up pipeline    # Run pipeline (one-shot, then exits)
```

### Service profiles:

```bash
# Infrastructure only (Kafka + Elasticsearch + Gateway + Drift Monitor)
docker compose up -d

# Run the pipeline (one-shot batch job)
docker compose --profile run up pipeline

# Stop everything
docker compose down

# Stop and remove volumes (clean slate)
docker compose down -v
```

### Docker Compose services:

| Service | Profile | Port | Description |
|---------|---------|------|-------------|
| `kafka` | default | 9092 | Apache Kafka 3.9.2 broker |
| `elasticsearch` | default | 9200 | Elasticsearch 8.12 (single-node) |
| `gateway` | default | 8000 | FastAPI gateway + dashboard API |
| `drift-monitor` | default | — | Continuous drift monitoring |
| `pipeline` | `run` | — | One-shot 11-layer pipeline run |

---

## Quick Commands Reference

### Setup (one-time)
```bash
# Install Python dependencies
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Install Node dependencies for UI
cd ckcSOC-ui && npm install && cd ..

# Pull LLM model
ollama pull llama3.2
```

### Run Pipeline
```bash
# Batch mode (simplest)
python datasets/hetero_dataset_builder.py && python run_demo.py --no-plots

# Streaming mode (requires Kafka)
docker compose up -d kafka elasticsearch
python run_demo.py --source kafka --no-plots

# With custom dataset
python run_demo.py --dataset path/to/events.json --no-plots

# Verbose mode (see per-event logs)
python run_demo.py --verbose --no-plots

# Limit to N events
python run_demo.py --limit 500 --no-plots
```

### View Results
```bash
# After pipeline runs, check outputs
cat state/sentinel_memory.json        # Detected incidents
cat state/playbooks.json              # Generated playbooks
cat state/audit_log.json              # Approval audit trail

# Open dashboard
cd ckcSOC-ui && npm run dev           # http://localhost:5173
```

### Infrastructure Management
```bash
# Health checks
docker compose ps                     # Show service status
curl http://localhost:9200/_cluster/health        # Elasticsearch
curl http://localhost:11434/api/tags              # Ollama

# Logs
docker compose logs -f kafka
docker compose logs -f elasticsearch

# Cleanup
docker compose down -v                # Remove all data
```

### Development
```bash
# API testing
curl http://localhost:8000/health
curl http://localhost:8000/api/dashboard/summary

# Run tests
python -m pytest tests/

# Dashboard dev server (with hot reload)
cd ckcSOC-ui && npm run dev
```

---

## Pipeline Layers

The LangGraph state machine orchestrates 11 sequential phases:

```
Ingest → Normalize → Correlate → Score → Explain → Attack Path
    → Playbook → AEGIS (governance) → Human Gate → Sentinel → Feedback
                         ↑                    │
                         └─── (rejected) ─────┘
```

| Layer | Phase | Module | Description |
|-------|-------|--------|-------------|
| 1 | **Ingest** | `phase1_ingest.py` | Auto-detect format (JSON/CSV/Syslog/KV/CEF/XML), parse & validate |
| 2 | **Normalize** | `phase2_normalize.py` | Map to canonical schema, risk hints, optional BERT NER |
| 3 | **Correlate** | `phase3_correlate.py` | Cluster related events by user/IP/time |
| 4 | **Score** | `phase4_score.py` | ML anomaly scoring (Isolation Forest, LOF, PyOD) |
| 5 | **Explain** | `phase5_explain.py` | Human-readable explainability narratives |
| 6 | **Playbook** | `phase6_playbook.py` | LLM-generated + template-based response playbooks |
| 7 | **AEGIS** | `phase7_aegis.py` | Governance checks, compliance validation |
| 8 | **Human Gate** | `phase8_approval.py` | Auto/manual approval with rejection → re-generation loop |
| 9 | **Sentinel** | `phase9_sentinel.py` | Store to sentinel memory + Elasticsearch |
| 10 | **Attack Path** | `phase10_attack_path.py` | Kill chain & attack graph mapping |
| 11 | **Feedback** | `phase11_retrain.py` | Model retraining triggers, feedback loop |

---

## Project Structure

```
ckcSOC/
├── api/
│   ├── gateway_api.py          # FastAPI gateway (auth, ingest, playbooks)
│   ├── dashboard_api.py        # Dashboard data endpoints
│   └── scorer_api.py           # Scoring API
│
├── pipeline/
│   ├── format_detector.py      # Auto-detect log format & normalize
│   ├── phase1_ingest.py        # Layer 1: Ingestion
│   ├── phase2_normalize.py     # Layer 2: Normalization
│   ├── phase3_correlate.py     # Layer 3: Correlation
│   ├── phase4_score.py         # Layer 4: ML Scoring
│   ├── phase5_explain.py       # Layer 5: Explainability
│   ├── phase6_playbook.py      # Layer 6: Playbook Generation
│   ├── phase7_aegis.py         # Layer 7: Governance (AEGIS)
│   ├── phase8_approval.py      # Layer 8: Human-in-the-Loop
│   ├── phase9_sentinel.py      # Layer 9: Sentinel Memory
│   ├── phase10_attack_path.py  # Layer 10: Attack Path Mapping
│   ├── phase11_retrain.py      # Layer 11: Feedback & Retrain
│   ├── drift_monitor.py        # Continuous drift detection
│   └── es_store.py             # Elasticsearch integration
│
├── kafka/
│   ├── topics.py               # Topic name definitions
│   ├── producer.py             # Kafka producer wrapper
│   ├── consumer.py             # Kafka consumer wrapper
│   ├── bus.py                  # In-memory bus (testing)
│   └── hetero_pusher.py        # Push raw logs to Kafka
│
├── datasets/
│   ├── hetero_dataset_builder.py     # Standard dataset generator
│   ├── hetero_dataset_builder_v2.py  # Competition stress-test generator
│   └── hetero_v2/                    # Generated per-topic JSONL files
│
├── schemas/v1/
│   ├── raw_event.json          # Raw event envelope schema
│   ├── normalized_event.json   # Normalized event schema
│   └── incident.json           # Incident schema
│
├── ckcSOC-ui/                  # React + TypeScript dashboard (Vite)
├── state/                      # Runtime state (pipeline output)
├── models/                     # ML model cache / HF NER models
├── tests/                      # pytest test suite
│
├── soc_graph.py                # LangGraph state machine definition
├── run_demo.py                 # Pipeline CLI entrypoint
├── run_compose_flow.py         # Kafka streaming validation
├── push_hetero_logs.py         # Push logs to Kafka
├── docker-compose.yml          # Docker services definition
├── Dockerfile                  # Pipeline container image
└── requirements.txt            # Python dependencies
```

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with timeout protection
pytest tests/ -v --timeout=60

# Run specific test
pytest tests/test_core_gate.py -v
pytest tests/test_v9_integration.py -v
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA_BOOTSTRAP` | `localhost:9092` | Kafka broker address |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama LLM server URL |
| `ES_URL` | `http://localhost:9200` | Elasticsearch URL |
| `HF_HOME` | `models/hf_ner` | HuggingFace model cache directory |
| `LOG_LEVEL` | `INFO` | Pipeline logging level (DEBUG, INFO, WARNING) |
| `PIPELINE_LIMIT` | (unlimited) | Max events to process in single run |
| `DRIFT_CHECK_INTERVAL` | `300` | Drift monitor check interval (seconds) |
| `PSI_THRESHOLD` | `0.2` | Population Stability Index alert threshold |
| `KS_THRESHOLD` | `0.15` | Kolmogorov-Smirnov test alert threshold |

### Set Environment Variables
```bash
# Linux/macOS
export OLLAMA_URL=http://localhost:11434
export KAFKA_BOOTSTRAP=localhost:9092
export ES_URL=http://localhost:9200
python run_demo.py --no-plots

# Windows (PowerShell)
$env:OLLAMA_URL="http://localhost:11434"
python run_demo.py --no-plots
```

---

## Troubleshooting

### Kafka won't start
```bash
# Check if port 9092 is already in use
lsof -i :9092

# Restart with clean state
docker compose down -v
docker compose up -d kafka
```

### Ollama connection refused
```bash
# Ensure Ollama is running
ollama serve

# Test connectivity
curl http://localhost:11434/api/tags

# If using Docker pipeline, verify host.docker.internal resolves
docker compose exec pipeline curl http://host.docker.internal:11434/api/tags
```

### Pipeline fails with "Dataset not found"
```bash
# Generate the dataset first
python datasets/hetero_dataset_builder.py

# Or for v2 competition dataset
python datasets/hetero_dataset_builder_v2.py
```

### Elasticsearch health check fails
```bash
# Check ES logs
docker compose logs elasticsearch

# Elasticsearch may need more memory
# Edit docker-compose.yml → ES_JAVA_OPTS=-Xms1g -Xmx1g
```

### `kafka-python` import conflicts
The project has a local `kafka/` directory that shadows the `kafka-python` package. The pusher scripts handle this by temporarily modifying `sys.path`. If you see import errors:
```bash
# Ensure kafka-python is installed in your venv
pip install kafka-python
```

### Dashboard can't connect to API
```bash
# Ensure the API gateway is running
uvicorn api.gateway_api:app --host 0.0.0.0 --port 8000

# Check CORS — the gateway allows all origins by default
curl http://localhost:8000/api/dashboard/summary
```

---

## Full Startup Sequence (All Services)

Here's the complete order to start everything from scratch:

```bash
# Terminal 1 — Ollama LLM
ollama serve

# Terminal 2 — Infrastructure
docker compose up -d kafka elasticsearch

# Wait for Kafka & ES to be healthy (~30-60s)
docker compose ps

# Terminal 3 — Generate data + Run pipeline
python datasets/hetero_dataset_builder_v2.py --events 5000
python run_demo.py --dataset datasets/hetero_v2_events.mixed --no-plots

# Terminal 4 — API Gateway
uvicorn api.gateway_api:app --host 0.0.0.0 --port 8000 --reload

# Terminal 5 — Dashboard UI
cd ckcSOC-ui && npm run dev

# Terminal 6 — Drift Monitor (optional)
python -m pipeline.drift_monitor

# Terminal 7 — Live Kafka stream (optional)
python push_hetero_logs.py --rate 200
```

Open **http://localhost:5173** to view the dashboard.

---

<p align="center"><strong>Built with ❤️ by Team CKC — Hack O Hire 2026</strong></p>
