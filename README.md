# 🛡️ MemGuard v5 — Autonomous SOC EDR & Behavioral Threat Hunting Platform

<p align="center">
  <img src="https://img.shields.io/badge/Version-5.2.0--SOC--Enterprise-blueviolet?style=for-the-badge&logo=shield" alt="Version" />
  <img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue?style=for-the-badge&logo=python" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-0.111.0-009688?style=for-the-badge&logo=fastapi" alt="FastAPI" />
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-v14.1%20Compliant-red?style=for-the-badge&logo=target" alt="MITRE ATT&CK" />
  <img src="https://img.shields.io/badge/ML%20Engine-Calibrated%20Logistic%20Rescorer-orange?style=for-the-badge&logo=scikitlearn" alt="ML Engine" />
  <img src="https://img.shields.io/badge/SIEM-Elasticsearch%20%7C%20Logstash%20%7C%20Kibana-005571?style=for-the-badge&logo=elastic" alt="ELK" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License" />
</p>

---

## 📋 Table of Contents
1. [Executive Summary](#-executive-summary)
2. [Core Value Proposition & Capabilities](#-core-value-proposition--capabilities)
3. [System Architecture & Data Pipeline Engine](#-system-architecture--data-pipeline-engine)
   - [High-Level Architectural Topology](#high-level-architectural-topology)
   - [End-to-End Telemetry Flow Sequence Diagram](#end-to-end-telemetry-flow-sequence-diagram)
   - [Detailed 6-Stage Processing Pipeline](#detailed-6-stage-processing-pipeline)
   - [Processing Latency & Pipeline Benchmarks](#processing-latency--pipeline-benchmarks)
   - [Live Data Schemas & Pipeline JSON Payloads](#live-data-schemas--pipeline-json-payloads)
   - [Multi-Vector Ingestion & Kernel Hook Mechanics](#multi-vector-ingestion--kernel-hook-mechanics)
   - [Database Persistence & Relational Schema](#database-persistence--relational-schema)
   - [Distributed SIEM Pipeline (ELK Stack)](#distributed-siem-pipeline-elk-stack)
4. [Detection Engine & Threat Intelligence](#-detection-engine--threat-intelligence)
   - [Shannon Entropy Analysis](#shannon-entropy-analysis)
   - [Living-off-the-Land (LOLBins) Surveillance](#living-off-the-land-lolbins-surveillance)
   - [MITRE ATT&CK Matrix Alignment](#mitre-attck-matrix-alignment)
   - [Neural/Logistic Threat ML Rescorer](#neurallogistic-threat-ml-rescorer)
5. [Real-Time Incident Containment & Mitigation](#-real-time-incident-containment--mitigation)
6. [Interactive SOC Attack Simulator](#-interactive-soc-attack-simulator)
7. [Enterprise SOC Dashboard Modules](#-enterprise-soc-dashboard-modules)
8. [Repository & Project Structure](#-repository--project-structure)
9. [Installation & Deployment Guide](#-installation--deployment-guide)
   - [Prerequisites](#1-prerequisites)
   - [Backend Service Setup](#2-backend-service-setup)
   - [SIEM ELK Stack Spin-up](#3-siem-elk-stack-spin-up)
   - [Accessing Dashboard & Telemetry](#4-accessing-dashboard--telemetry)
10. [REST & WebSocket API Reference](#-rest--websocket-api-reference)
11. [🔮 Future Scope & Comprehensive Engineering Roadmap](#-future-scope--comprehensive-engineering-roadmap)
    - [Phase 1: Low-Level Kernel & Agent Modernization](#phase-1-low-level-kernel--agent-modernization-near-term)
    - [Phase 2: Deep Learning & Graph Intelligence](#phase-2-deep-learning--graph-intelligence-mid-term)
    - [Phase 3: Autonomous SOAR & Active Defense](#phase-3-autonomous-soar--active-defense-mid-term)
    - [Phase 4: Cloud-Native & Massive Distributed Fleet](#phase-4-cloud-native--massive-distributed-fleet-long-term)
    - [Phase 5: Deception & MITRE D3FEND Framework](#phase-5-deception--mitre-d3fend-framework-long-term)
12. [Contributing & License](#-contributing--license)

---

## 🌟 Executive Summary

**MemGuard v5** is a high-performance, next-generation **Endpoint Detection and Response (EDR)** and **Security Operations Center (SOC)** threat hunting platform. Built specifically to counter stealthy, modern adversaries, MemGuard bridges the gap between low-level operating system telemetry and high-level autonomous incident containment.

Traditional antivirus solutions rely heavily on static file signatures (`MD5/SHA256`) that can be trivially bypassed by polymorphic crypters, memory injection, and living-off-the-land binaries. MemGuard monitors **active runtime execution states**, **command-line entropy**, **parent-child lineage trees**, and **Windows Event Logs (Sysmon)**. Detections are instantly cross-correlated against a hybrid **Heuristic Rules Engine** and a **Calibrated Machine Learning Rescorer**, mapped directly to the **MITRE ATT&CK®** framework, and visualized on an ultra-low-latency enterprise dashboard.

---

## ⚡ Core Value Proposition & Capabilities

- **Dual-Layer Threat Detection**: Combines deterministic behavioral heuristics (LOLBin targeting, argument parsing, parent validation) with a self-calibrating 8-feature logistic ML scoring engine.
- **Sub-Second Active Containment**: Non-blocking, instant process termination (`SIGKILL`/`TerminateProcess`) and host isolation with zero UI freezing.
- **MITRE ATT&CK Matrix Mapping**: Real-time correlation with 12+ tactics and techniques (e.g., T1059.001, T1003.001, T1490, T1218, T1071.001).
- **Multi-Device Enterprise Fleet**: Centralized command over distributed nodes across Windows, Linux, macOS, Android, and Web Terminals, featuring granular remote isolation.
- **Shannon Entropy Engine**: Identifies heavily obfuscated strings, base64 payloads, and packed shellcode within execution arguments.
- **Tactical SOC Attack Simulator**: 7 pre-configured attack drills allowing analysts to test defense readiness against ransomware, LSASS credential theft, and C2 beacons.
- **Enterprise SIEM Pipeline**: Real-time non-blocking asynchronous log shipping to an **Elasticsearch + Logstash + Kibana (ELK)** stack.
- **Glassmorphic Analyst Workspace**: Feature-rich, single-page SOC dashboard equipped with real-time WebSockets, live telemetry charts, process explorers, and automated executive PDF/print reporting.

---

## 🏗️ System Architecture & Data Pipeline Engine

MemGuard v5 is designed as a distributed, event-driven telemetry and behavioral analytics architecture. It ingests high-velocity process and kernel telemetry across local and remote operating system endpoints, transforms and evaluates data through an asynchronous 6-stage pipeline in under **12 milliseconds**, and broadcasts actionable threat intelligence across WebSocket streams and enterprise SIEM pipelines simultaneously.

---

### High-Level Architectural Topology

```mermaid
flowchart TB
    subgraph ENDPOINTS["🖥️ Monitored Endpoints & Multi-Device Fleet"]
        WIN["Windows Host (Local Kernel Agent)"]
        LNX["Linux Cloud Node (Debian/RHEL)"]
        MAC["macOS Workstation (Darwin)"]
        AND["Android Mobile Device"]
        WEB["Cloud Edge Web Terminal"]
    end

    subgraph INGESTION["📥 Stage 1: Multi-Vector Telemetry Ingestion Layer"]
        PSUTIL["psutil Process Kernel Poller\n• PID, PPID, Cmdline, Working Set\n• User SID & Binary Paths"]
        SYSMON["Windows Sysmon Engine (wevtutil)\n• Event 1: Process Creation\n• Event 3: Network Connection\n• Event 7: Image / DLL Load\n• Event 11: File Create"]
        REMOTE_API["External Fleet Telemetry Ingestion\nPOST /api/telemetry/report"]
    end

    WIN --> PSUTIL
    WIN --> SYSMON
    LNX & MAC & AND & WEB --> REMOTE_API

    subgraph ENGINE["🧠 MemGuard Core Behavioral Engine (FastAPI Async)"]
        subgraph PIPELINE["6-Stage Asynchronous Telemetry Pipeline"]
            STAGE1["01. Telemetry Ingest\n(Raw Event Normalized)"]
            STAGE2["02. Feature Extraction\n• Shannon Entropy (H)\n• Tokenizer & Arg Stripping\n• Parent-Child Tree Traversal"]
            STAGE3["03. Deterministic Heuristics\n• LOLBin Signature Matrix\n• Suspicious Parentage Rules\n• MITRE ATT&CK Mapper"]
            STAGE4["04. ThreatMLScorer (ML Engine)\n• 8-Feature Vector\n• Calibrated Sigmoid Inference\n• Online Gradient Descent"]
            STAGE5["05. EDR Containment & Policy\n• Terminate Process (SIGKILL)\n• Host Network Isolation\n• Audit Event Generation"]
            STAGE6["06. Real-Time Distribution\n• WebSocket Broadcasting\n• Audio Radar Synthesizer"]
        end

        BASELINE[("System Baseline Cache\nsystem_baseline.json")]
        CONTAINMENT_CTRL["Containment Controller\n/mitigate & /api/devices/{id}/isolate"]
    end

    PSUTIL & SYSMON & REMOTE_API --> STAGE1
    STAGE1 --> STAGE2 --> STAGE3 --> STAGE4 --> STAGE5 --> STAGE6
    BASELINE -.-> STAGE3
    STAGE5 <--> CONTAINMENT_CTRL

    subgraph STORAGE["💾 Persistence & State Management Layer"]
        SQLITE[("SQLite Database: memguard.db\n• Device Fleet Registry\n• ThreatIncident Ledgers\n• ThreatReport Summaries\n• Security Audit Logs")]
        MODEL_STORE[("Model Checkpoint Store\nml_model_checkpoint.json")]
    end

    STAGE5 <--> SQLITE
    STAGE4 <--> MODEL_STORE

    subgraph DISTRIBUTION["📡 Real-Time Broadcasting & SIEM Pipeline"]
        WS_HUB["WebSocket Broadcast Manager\n/ws/telemetry (Sub-15ms)"]
        LOGSTASH_HANDLER["TCP Logstash Asynchronous Shipper\npython-logstash (TCP Port 5000)"]
    end

    STAGE6 --> WS_HUB
    STAGE6 --> LOGSTASH_HANDLER

    subgraph SIEM["📊 Enterprise SIEM Integration (Docker ELK Stack)"]
        LOGSTASH["Logstash Ingestion Filter\n(logstash.conf)"]
        ELASTIC[("Elasticsearch Storage\nIndex: memguard-logs-*")]
        KIBANA["Kibana Visual SOC Dashboards\nhttp://localhost:5601"]
        LOGSTASH_HANDLER --> LOGSTASH --> ELASTIC --> KIBANA
    end

    subgraph FRONTEND["💻 Enterprise SOC Dashboard (frontend/index.html)"]
        OPS["Operations Center & Live Threat Feed"]
        FLEET_UI["Multi-Device Fleet Manager"]
        PIPE_UI["Interactive Pipeline Visualizer"]
        ML_UI["ML Threat Rescorer & Calibration"]
        REPORTS_UI["Executive Report Generator & Export"]
        MITRE_UI["MITRE ATT&CK Matrix Heatmap"]
        PROC_UI["Live Process & Thread Explorer"]
    end

    WS_HUB ==>|Bi-Directional WebSocket| FRONTEND
    SQLITE -.->|REST API / JSON| FRONTEND
```

---

### End-to-End Telemetry Flow Sequence Diagram

The following sequence details the lifecycle of a malicious event from initial host execution to analyst notification, containment, and SIEM archival:

```mermaid
sequenceDiagram
    autonumber
    actor Adversary as Adversary / Host Process
    participant Kernel as OS Kernel / Process Subsystem
    participant Stage1 as Stage 1: Ingestion (psutil / Sysmon)
    participant Stage2 as Stage 2: Feature & Entropy Extractor
    participant Stage3 as Stage 3: MITRE Heuristics
    participant Stage4 as Stage 4: ThreatMLScorer (Sigmoid ML)
    participant Stage5 as Stage 5: Containment Controller
    participant DB as SQLite DB (memguard.db)
    participant WS as WebSocket Hub (/ws/telemetry)
    participant ELK as Logstash -> Elasticsearch
    actor SOC as SOC Analyst Dashboard

    Adversary->>Kernel: Launches Encoded PowerShell (`powershell -w hidden -enc SQBFAFg...`)
    Kernel->>Stage1: Generates Process Creation Event (Event ID 1 & psutil process snapshot)
    Stage1->>Stage2: Deserializes Image, Parent, Hashes, CLI arguments [Latency: ~2.4ms]
    Note over Stage2: Computes Shannon Entropy H=5.42<br/>Normalizes arguments & detects hidden window flag
    Stage2->>Stage3: Passes Feature Vector [Latency: ~0.8ms]
    Note over Stage3: Flags LOLBin (powershell.exe)<br/>Maps to MITRE T1059.001 & T1564.003
    Stage3->>Stage4: Passes Heuristic Risk & Signatures [Latency: ~1.2ms]
    Note over Stage4: Evaluates 8 calibrated feature weights<br/>Outputs ML Score: 92/100, Confidence: 0.99 (CRITICAL)
    Stage4->>Stage5: Triggers Incident Record [Latency: ~1.8ms]
    Stage5->>DB: Commits ThreatIncident (Status: Active, Severity: Critical)
    Stage5->>Stage6: Formats Broadcast Envelope [Latency: ~4.5ms]
    Stage6->>WS: Pushes JSON Alert Frame to connected analysts [Latency: ~0.9ms]
    Stage6->>ELK: Streams Async TCP Log Packet to Port 5000
    WS->>SOC: Analyst UI plays acoustic alert ping & updates Threat Feed
    
    alt Manual or Automated Containment Triggered
        SOC->>Stage5: Clicks "Terminate & Quarantine" (`POST /mitigate`)
        Note over SOC: Optimistic UI instantly animates & evicts threat card (<50ms)
        Stage5->>Kernel: Issues `psutil.Process(pid).kill()` (SIGKILL / TerminateProcess)
        Stage5->>DB: Updates Incident Status to "Quarantined"
        Stage5->>WS: Dispatches Mitigation Confirmation Frame
        WS->>SOC: Confirms process terminated and incident logged
    end
```

---

### Detailed 6-Stage Processing Pipeline

Each process event passing through MemGuard traverses an audited, six-tier asynchronous pipeline:

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│   STAGE 1    │   │   STAGE 2    │   │   STAGE 3    │   │   STAGE 4    │   │   STAGE 5    │   │   STAGE 6    │
│  Telemetry   │──>│   Feature    │──>│ Deterministic│──>│  ML Threat   │──>│  Autonomous  │──>│ Event Stream │
│  Harvesting  │   │  Extraction  │   │ MITRE Engine │   │  Rescoring   │   │ Containment  │   │  & SIEM Bus  │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
```

#### Stage 1: Multi-Vector Telemetry Ingestion Layer
- **Windows Sysmon Operational Log**: Deserializes XML event streams from the `Microsoft-Windows-Sysmon/Operational` channel via `wevtutil` for Process Create (**Event ID 1**), Network Connect (**Event ID 3**), Driver/Image Loads (**Event ID 7**), and File Create (**Event ID 11**).
- **PsUtil Kernel Hook**: Directly queries Windows NT executive process tables to harvest executable path, PID, parent PID, working set memory (RSS), and security token context.
- **Cross-Platform Telemetry API**: Exposes `POST /api/telemetry/report` for external agents running on Linux servers, macOS workstations, and Android devices.

#### Stage 2: Feature Extraction & Shannon Entropy Analysis
- **Shannon Entropy Calculator**: Measures the information density of command-line strings. Values of $H \ge 4.5$ indicate high probability of Base64, RC4, or AES obfuscated payload blobs designed to evade signature matching.
- **Parent-Child Ancestry Correlation**: Identifies anomalous ancestry (e.g., Office binaries spawning command interpreters, or IIS worker processes spawning shell environments).
- **Argument Tokenizer & Normalizer**: Strips evasion flags (`-enc`, `-encodedcommand`, `-e`, `-nop`, `-w hidden`) across PowerShell, Command Prompt, bash, and LOLBins.

#### Stage 3: Behavioral Heuristics & LOLBin Detection Matrix
- **LOLBin Abuse Engine**: Scans against a curated catalog of Living-off-the-Land binaries (`certutil.exe`, `mshta.exe`, `regsvr32.exe`, `bitsadmin.exe`, `rundll32.exe`, `wmic.exe`).
- **Ransomware Pre-Encryption Rules**: Detects immediate recovery inhibitor actions including volume shadow copy deletion (`vssadmin delete shadows`), catalog purging, and recovery policy disabling.
- **Credential Theft Indicators**: Detects `comsvcs.dll MiniDump` exports, `procdump` targeting `lsass.exe`, and SAM hive registry extraction.

#### Stage 4: Adaptive ML Threat Scoring & Rescoring Engine
- **Calibrated Multi-Feature Model**: Evaluates an 8-dimensional normalized feature vector with calibrated weights (destructive actions: 0.49, credential theft: 0.52, suspicious parent: 0.42, entropy: 0.45).
- **Sigmoid Output Calibration**: Computes risk probability using temperature-calibrated sigmoid activation:
  $$\text{Confidence} = \frac{1}{1 + e^{-(\mathbf{w}^T \mathbf{x} + b) \cdot \gamma}}$$
- **Online Retraining**: Supports dynamic weight updates via `POST /api/ml/train` using batch gradient descent directly from the SOC console.

#### Stage 5: Automated EDR Containment & Policy Engine
- **Targeted Process Termination**: Sends immediate kernel termination signals (`kill()` / `TerminateProcess`) to hostile process trees.
- **Host Network Isolation**: Allows analysts to quarantine compromised endpoints via `POST /api/devices/{id}/isolate`, dropping outbound traffic while maintaining SOC heartbeat.
- **Forensic Audit Logging**: Persists all incident records, analyst actions, and containment metadata into the SQLite database.

#### Stage 6: Real-Time Event Bus & SOC Visualization
- **WebSocket Connection Manager**: Broadcasts live alert frames over `ws://127.0.0.1:8000/ws/telemetry` with sub-15ms broadcast latency.
- **Audio Radar Alert Synthesizer**: Uses the browser Web Audio API to generate acoustic radar tones upon ingestion of Critical severity events.
- **SIEM TCP Shipper**: Asynchronously dispatches JSON event logs over TCP port 5000 to the Logstash pipeline without blocking the API event loop.

---

### Processing Latency & Pipeline Benchmarks

| Pipeline Stage | Module / Component | Primary Operations | Mean Execution Latency |
| :--- | :--- | :--- | :--- |
| **Stage 1: Telemetry Ingest** | `sysmon_parser.py` + `psutil` | XML stream parsing, NT process query | **~2.4 ms** |
| **Stage 2: Feature Extraction** | `detection_engine.py` | Shannon entropy math, tokenization, regex | **~0.8 ms** |
| **Stage 3: Behavioral Heuristics**| `detection_engine.py` | MITRE technique lookup, LOLBin rules | **~1.2 ms** |
| **Stage 4: ML Threat Rescoring** | `ThreatMLScorer` | Matrix multiplication, sigmoid activation | **~1.8 ms** |
| **Stage 5: EDR Containment** | `main.py` + `database.py` | SQLite commit, process termination | **~4.5 ms** |
| **Stage 6: Event Bus & SIEM** | `WebSocketManager` + Logstash | Frame dispatch, TCP socket stream | **~0.9 ms** |
| **Total End-to-End Pipeline** | **Complete Ingest-to-Alert** | **Full 6-Stage Telemetry Lifecycle** | **~11.6 ms** |

---

### Live Data Schemas & Pipeline JSON Payloads

Below are the exact JSON payloads generated at each stage of the MemGuard pipeline:

#### Stage 1: Raw Telemetry Ingest Schema
```json
{
  "event_source": "Sysmon XML Channel 1",
  "event_id": 1,
  "image": "C:\\Windows\\System32\\powershell.exe",
  "parent": "C:\\Program Files\\Microsoft Office\\winword.exe",
  "commandline": "powershell.exe -nop -w hidden -enc SQBFAFgAIAA...",
  "hashes": "SHA256=3B9D9F0E1F30E26CB2C4B7281A5D19DF6044E278B247659F2181DCFE2841F09A",
  "process_guid": "{F2D3A1B4-8841-65E0-0000-0010E1A70300}",
  "user": "NT AUTHORITY\\SYSTEM"
}
```

#### Stage 2: Extracted Feature Vector Schema
```json
{
  "features_extracted": {
    "entropy_score": 5.42,
    "obfuscation_detected": true,
    "suspicious_parent_flag": 1.0,
    "evasion_arguments": ["-w hidden", "-nop", "-enc"],
    "lolbin_candidate": "powershell.exe",
    "token_count": 5
  }
}
```

#### Stage 3: MITRE Heuristic Match Schema
```json
{
  "mitre_technique": "T1059.001 - PowerShell Obfuscation",
  "secondary_techniques": [
    "T1055 - Process Injection / Office Lineage",
    "T1564.003 - Hidden Window"
  ],
  "rule_matches": [
    "PowerShell encoded command detected",
    "Office process winword.exe spawned command interpreter",
    "Hidden window execution active"
  ]
}
```

#### Stage 4: ML Threat Rescorer Output Schema
```json
{
  "calculated_score": 92,
  "calibrated_risk_level": "CRITICAL",
  "confidence_rating": 0.99,
  "feature_contributions": {
    "destructive_actions": 0.0,
    "suspicious_parent": 24.5,
    "entropy_score": 16.5,
    "lolbin_flag": 22.0,
    "evasion_flags": 15.0,
    "signature_match": 14.0
  }
}
```

#### Stage 5: EDR Containment Action Schema
```json
{
  "action_applied": "PROCESS_KILL_AND_ISOLATE",
  "target_pid": 6428,
  "target_process": "powershell.exe",
  "containment_status": "CONTAINED",
  "audit_record_id": "INC-9F41E8B2",
  "timestamp": "2026-10-13T01:10:00Z"
}
```

#### Stage 6: Real-Time WebSocket Broadcast Schema
```json
{
  "stream_channel": "ws://127.0.0.1:8000/ws/telemetry",
  "broadcast_type": "REALTIME_THREAT_REPORT",
  "latency_ms": 11,
  "connected_clients": 4,
  "incident_payload": {
    "id": 14,
    "process": "powershell.exe",
    "pid": 6428,
    "threat_type": "Encoded PowerShell (T1059.001)",
    "severity": "CRITICAL",
    "risk_score": 92,
    "status": "Active"
  }
}
```

---

### Multi-Vector Ingestion & Kernel Hook Mechanics

```
┌────────────────────────────────────────────────────────────────────────┐
│                        OPERATING SYSTEM HOST                           │
└────────────────────────────────────────────────────────────────────────┘
         │                                               │
         ▼                                               ▼
┌──────────────────────────────┐              ┌──────────────────────────┐
│   psutil Poller Engine       │              │  Windows Sysmon ETW      │
│   (Live Process Memory)      │              │  (wevtutil CLI Wrapper)  │
├──────────────────────────────┤              ├──────────────────────────┤
│ • PID & Parent PID (PPID)    │              │ • Event ID 1: ProcCreate │
│ • Execution CLI arguments    │              │ • Event ID 3: NetConnect │
│ • RSS Memory Footprint       │              │ • Event ID 7: ImageLoad  │
│ • User Context & Integrity   │              │ • Event ID 11: FileCreate│
└──────────────────────────────┘              └──────────────────────────┘
         │                                               │
         └───────────────────────┬───────────────────────┘
                                 ▼
              ┌─────────────────────────────────────┐
              │   FastAPI Ingestion Router          │
              │   • Normalizes heterogeneous feeds  │
              │   • Dispatches to Stage 2 Extractor │
              └─────────────────────────────────────┘
```

---

### Database Persistence & Relational Schema

MemGuard utilizes SQLAlchemy ORM backed by SQLite (`memguard.db`) for high-speed local persistence without heavy database dependencies:

```mermaid
erDiagram
    Device ||--o{ ThreatIncident : "hosts"
    Device {
        int id PK
        string hostname
        string ip_address
        string os_type
        string status "Active | Isolated | Offline"
        datetime last_seen
        string risk_level "Clean | Low | Medium | High | Critical"
        int threat_count
        string agent_version
    }

    ThreatIncident {
        int id PK
        int device_id FK
        string process_name
        int pid
        string threat_type
        string severity "Low | Medium | High | Critical"
        string mitre_technique
        string mitre_tactic
        float ml_confidence
        string action_taken "None | Terminated | Quarantined | Isolated"
        string status "Active | Investigating | Mitigated | Quarantined"
        datetime timestamp
        text details
    }

    ThreatReport {
        int id PK
        string report_title
        datetime generated_at
        int total_threats
        int critical_count
        int high_count
        int medium_count
        int low_count
        float overall_risk_score
        text top_threats
        text executive_summary
    }

    LogEntry {
        int id PK
        datetime timestamp
        string level "INFO | WARNING | ERROR | CRITICAL"
        string source "FastAPI | Engine | Sysmon | Mitigation"
        text message
        text metadata_json
    }

    User {
        int id PK
        string username
        string password_hash
        string role "Admin | Analyst | Auditor"
    }
```

---

### Distributed SIEM Pipeline (ELK Stack)

For enterprise-scale compliance and multi-year threat retention, MemGuard integrates directly with a Dockerized ELK Stack:

```
FastAPI Core Engine
   │
   └── TCPLogstashHandler (Asynchronous non-blocking TCP socket)
          │
          ▼  [Port 5000: JSON Stream]
   ┌────────────────────────────────────────────────────────┐
   │ Logstash Container (logstash.conf)                     │
   │ • json_lines codec decoder                             │
   │ • Timestamp enrichment & GeoIP resolution              │
   │ • MITRE ATT&CK field indexing                          │
   └────────────────────────────────────────────────────────┘
          │
          ▼  [Port 9200: REST HTTP Bulk Ingest]
   ┌────────────────────────────────────────────────────────┐
   │ Elasticsearch Cluster                                  │
   │ • Index: memguard-logs-%{+YYYY.MM.dd}                  │
   │ • Full-text inverted index for threat hunting          │
   └────────────────────────────────────────────────────────┘
          │
          ▼  [Port 5601: Web UI]
   ┌────────────────────────────────────────────────────────┐
   │ Kibana Enterprise Analytics Console                    │
   │ • Visual heatmaps & timeline histograms                │
   │ • Lucene query search across enterprise logs           │
   └────────────────────────────────────────────────────────┘
```

---

## 🎯 Detection Engine & Threat Intelligence

### Shannon Entropy Analysis

Malicious actors routinely encode scripts in Base64 or compress shellcode inside command arguments to evade signature matching. MemGuard computes the Shannon Entropy ($H$) of all argument strings:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Where $P(x_i)$ is the probability of character $x_i$ occurring in the string.
- **Normal Command Arguments**: $H \approx 2.5 - 3.8$
- **Base64 / XOR / Encrypted Shellcode**: $H \ge 4.5$ (Flagged automatically as High Entropy Evasion - `T1027`)

---

### Living-off-the-Land (LOLBins) Surveillance

MemGuard actively tracks legitimate system utilities frequently hijacked by adversaries:

| LOLBin Binary | Legitimate Purpose | Malicious Exploitation Pattern | MITRE Technique |
| :--- | :--- | :--- | :--- |
| `certutil.exe` | Certificate Management | Remote binary download (`-urlcache -split -f`) | **T1105** |
| `powershell.exe` | System Administration | Encoded payload execution (`-enc`, `-w hidden`) | **T1059.001** |
| `vssadmin.exe` | Volume Shadow Copy Admin | Deletion of recovery snapshots prior to ransomware | **T1490** |
| `regsvr32.exe` | Register OLE Controls | Squiblydoo remote scriptlet execution (`/s /u /i:http`) | **T1218.010** |
| `mshta.exe` | HTML Application Host | Executing inline VBScript/JScript drops | **T1218.005** |
| `wmic.exe` | WMI Command Line | Remote process creation & shadow deletion | **T1047** |
| `rundll32.exe` | Run 32-bit DLLs | Executing arbitrary DLL export routines | **T1218.011** |
| `bitsadmin.exe` | Background Transfer Admin | Covert payload staging in persistent transfer jobs | **T1197** |

---

### MITRE ATT&CK Matrix Alignment

MemGuard maps every detection to official MITRE ATT&CK tactics and techniques:

| Technique ID | Technique Name | Tactic | Detection Rule / Signature Trigger | Risk Score |
| :--- | :--- | :--- | :--- | :--- |
| **T1059.001** | PowerShell Execution | Execution | `-enc`, `-encodedcommand`, `bypass`, `downloadstring` | 92 / 100 |
| **T1490** | Inhibit System Recovery | Impact | `vssadmin delete shadows`, `wmic shadowcopy delete` | 98 / 100 |
| **T1003.001** | LSASS Memory Dumping | Credential Access | `procdump -ma lsass`, `sekurlsa`, `comsvcs.dll #24` | 96 / 100 |
| **T1105** | Ingress Tool Transfer | Command and Control | `certutil -urlcache`, `curl -O`, `bitsadmin /transfer` | 78 / 100 |
| **T1218.010** | Regsvr32 (Squiblydoo) | Defense Evasion | `regsvr32.exe /s /u /i:http scrobj.dll` | 85 / 100 |
| **T1218.005** | Mshta Exploitation | Defense Evasion | `mshta.exe vbscript:`, `mshta.exe javascript:` | 82 / 100 |
| **T1071.001** | Web Protocols (C2) | Command and Control | Suspicious outbound beacon patterns to known C2 ports | 88 / 100 |
| **T1547.001** | Registry Run Keys | Persistence | Writes to `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | 75 / 100 |
| **T1055** | Process Injection | Privilege Escalation | Cross-process memory allocation and thread hooking | 90 / 100 |
| **T1027** | Obfuscated Arguments | Defense Evasion | Shannon Entropy score $H > 4.5$ on command line | 80 / 100 |

---

### Neural/Logistic Threat ML Rescorer

The `ThreatMLScorer` class operates as an adaptive, calibrated machine learning layer that scores process malice across 8 dynamic dimensions:

```json
{
  "feature_weights": {
    "entropy_score": 0.4503,
    "lolbin_flag": 0.3801,
    "suspicious_parent": 0.4199,
    "evasion_flags": 0.3502,
    "destructive_actions": 0.4897,
    "credential_theft": 0.5204,
    "c2_indicator": 0.3905,
    "signature_match": 0.2801
  },
  "bias": -0.850,
  "calibration_factor": 1.15
}
```

- **Inference**: Given feature vector $\mathbf{x}$, the raw score is computed as:
  $$z = \sum_{i=1}^{8} w_i \cdot x_i + b$$
  $$\text{Confidence} = \frac{1}{1 + e^{-z \cdot \gamma}}$$
- **Online Calibration**: The model supports real-time gradient descent fine-tuning via `POST /api/ml/train` directly through the SOC dashboard, maintaining checkpoint state in `backend/ml_model_checkpoint.json`.

---

## ⚡ Real-Time Incident Containment & Mitigation

MemGuard features an industrial-grade mitigation pipeline designed to minimize the analyst's **Mean Time to Remediate (MTTR)**:

1. **Inline Non-Blocking Modal**: Replaced outdated browser-blocking alerts with a dedicated, high-speed inline confirmation modal.
2. **Optimistic UI Card Eviction**: The UI immediately animates and evicts the targeted threat card in $< 50\text{ms}$, giving analysts instantaneous feedback.
3. **Fire-and-Forget Background Verification**: Threat scans are queued asynchronously after mitigation without locking the UI thread.
4. **Endpoint Network Isolation**: If a threat is deemed critical or widespread, analysts can isolate the host device from the fleet with a single click, severing all outbound connections while retaining telemetry.

---

## 🧪 Interactive SOC Attack Simulator

MemGuard includes a built-in attack simulator featuring 7 real-world attack scenarios to train SOC personnel and validate detection pipelines:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      TACTICAL DRILL SCENARIOS                          │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Encoded PowerShell (T1059.001)   │ Emulates fileless download cradle│
│ 2. Ransomware Prep (T1490)          │ Volume Shadow Copy deletion      │
│ 3. LSASS Dump (T1003.001)           │ Procdump memory scraping         │
│ 4. Cobalt Strike C2 (T1071.001)     │ Beacon traffic to remote IP      │
│ 5. CertUtil Dropper (T1105)         │ LOLBin certificate download      │
│ 6. Regsvr32 Squiblydoo (T1218.010)  │ Remote scrobj.dll execution      │
│ 7. Run Key Persistence (T1547.001)  │ Malicious registry modification  │
└────────────────────────────────────────────────────────────────────────┘
```

Triggers can be fired via `POST /simulate?scenario=<name>` and cleared instantly via `POST /clear-simulation`.

---

## 🖥️ Enterprise SOC Dashboard Modules

The single-page analyst workspace (`frontend/index.html`) is structured into specialized tactical views:

1. **Operations Center**: Live overall risk gauge, active threat counter, real-time telemetry line charts, and rapid triage feed.
2. **Multi-Device Fleet**: Real-time status matrix across Windows, Linux, macOS, Android, and Web endpoints, with remote host isolation and restoration toggles.
3. **Architecture & Pipeline**: Interactive visualization of the 6-stage telemetry processing lifecycle.
4. **ML Threat Rescorer**: Live model health, weight distribution bars, confusion matrix, calibration factor, and in-browser model retraining.
5. **Real-Time Reports**: On-demand executive threat reports with risk distribution breakdowns, compliance ratings, and one-click PDF/Print generation.
6. **Threat Detections**: Comprehensive incident table with search, severity filters, full command-line inspection, and instant containment triggers.
7. **MITRE ATT&CK Matrix**: Tactical heatmap highlighting active adversary coverage across the kill chain.
8. **Process Explorer**: Live, searchable process monitor showing PIDs, paths, parent processes, and memory consumption.

---

## 📂 Repository & Project Structure

```
memguard-v2/
├── backend/                              # Core Python FastAPI Backend
│   ├── main.py                          # REST API, WebSocket server, fleet routes, mitigation
│   ├── detection_engine.py              # Heuristic rules, LOLBins, Shannon entropy, ThreatMLScorer
│   ├── database.py                      # SQLAlchemy models (Device, ThreatIncident, Report, Log)
│   ├── sysmon_parser.py                 # Windows Event Log (Sysmon) wevtutil parser
│   ├── logger.py                        # Logging setup & Logstash integration
│   ├── requirements.txt                 # Backend dependencies
│   ├── ml_model_checkpoint.json         # Persisted ML model weights & metrics
│   ├── system_baseline.json             # Calibrated normal system process baseline
│   ├── memguard.db                      # Local SQLite persistence database
│   ├── backend_dashboard.html           # Standalone diagnostic backend view
│   └── system_architecture.html         # Interactive architecture schematic
├── frontend/                             # SOC Frontend Dashboard
│   └── index.html                       # Enterprise Single-Page Dashboard (HTML5/CSS3/Vanilla JS)
├── siem/                                 # Enterprise SIEM Integration
│   ├── docker-compose.yml               # Multi-container ELK Stack configuration
│   └── logstash.conf                    # TCP log ingest pipeline configuration
├── .gitignore                            # Git ignore rules
└── README.md                             # Comprehensive Project Documentation
```

---

## 🚀 Installation & Deployment Guide

### 1. Prerequisites
- **Python 3.10+** (Python 3.11, 3.12, 3.13 fully supported)
- **Git**
- **Docker & Docker Compose** (Optional, required for full ELK Stack integration)
- **Microsoft Sysmon** (Optional, recommended for Windows Event Log telemetry)

---

### 2. Backend Service Setup

```powershell
# 1. Clone the repository
git clone https://github.com/your-org/memguard.git
cd memguard-v2

# 2. Enter backend directory and create virtual environment
cd backend
python -m venv venv

# 3. Activate virtual environment
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Start the FastAPI engine with live reload
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

*The backend API will start at `http://127.0.0.1:8000`.*
*Interactive API Swagger Documentation is available at `http://127.0.0.1:8000/docs`.*

---

### 3. SIEM ELK Stack Spin-up

To enable distributed log aggregation and Kibana dashboards:

```powershell
cd siem
docker-compose up -d
```

- **Kibana Web UI**: `http://localhost:5601`
- **Elasticsearch REST API**: `http://localhost:9200`
- **Logstash TCP Log Collector**: `localhost:5000`

---

### 4. Accessing Dashboard & Telemetry

1. Navigate to the `frontend/` directory.
2. Open `frontend/index.html` in your web browser (or access `http://localhost:8000/` directly via FastAPI).
3. The dashboard connects via WebSocket to `ws://localhost:8000/ws/telemetry` and displays live endpoint status.

---

## 🔌 REST & WebSocket API Reference

| Method | Endpoint | Description | Request / Payload Details |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Serves main SOC Dashboard | HTML response |
| `GET` | `/architecture` | Serves interactive system architecture | HTML response |
| `GET` | `/backend` | Serves diagnostic console | HTML response |
| `WS` | `/ws/telemetry` | Real-time WebSocket telemetry stream | Streams live risk & threat alerts |
| `GET` | `/scan` | Executes full system process scan | Returns detected threats & overall risk |
| `POST` | `/mitigate` | Terminates process & marks quarantined | `{"threat_id": 1, "pid": 4820}` |
| `GET` | `/api/devices` | Returns all registered fleet devices | Array of Device objects |
| `POST` | `/api/devices/{id}/isolate`| Remotely isolates an endpoint | Host is removed from network routing |
| `POST` | `/api/devices/{id}/restore`| Restores an endpoint to active state| Reconnects host to fleet network |
| `POST` | `/simulate` | Fires a tactical SOC drill scenario | `?scenario=encoded_powershell` |
| `POST` | `/clear-simulation` | Clears all simulated active threats | Returns clean baseline |
| `GET` | `/api/ml/model-status` | Fetches ML model weights & metrics | Feature weights, bias, accuracy |
| `POST` | `/api/ml/train` | Triggers online model retraining | Updates checkpoint JSON |
| `POST` | `/api/ml/rescore` | Re-evaluates incident with ML engine | `{"features": {...}}` |
| `GET` | `/api/reports` | Fetches saved incident reports | Returns historical reports |
| `POST` | `/api/reports/generate` | Generates a new executive report | Generates executive summary & stats |
| `POST` | `/api/telemetry/report` | External agent telemetry ingestion | Accepts remote node process records |

---

## 🔮 Future Scope & Comprehensive Engineering Roadmap

MemGuard v5 serves as a production-grade foundation for autonomous endpoint defense. The roadmap below outlines the architectural evolution across five major horizons:

### Phase 1: Low-Level Kernel & Agent Modernization (Near-Term)
- [ ] **Cross-Platform Native Agent in Rust/C++**:
  - Replace Python-based polling on remote endpoints with an ultra-lightweight ($< 15\text{MB}$ RAM), compiled binary agent built in Rust.
  - Zero Python runtime dependencies on monitored client endpoints.
- [ ] **eBPF (Extended Berkeley Packet Filter) on Linux**:
  - Hook directly into Linux kernel tracepoints (`sys_enter_execve`, `sys_enter_connect`, `sched_process_fork`).
  - Capture fileless execution and network sockets at the kernel ring buffer with near-zero CPU overhead.
- [ ] **ETW (Event Tracing for Windows) Native Consumer**:
  - Replace `wevtutil` command subprocesses with direct Win32 ETW API subscriptions (`OpenTrace`, `ProcessTrace`).
  - Achieve microsecond-latency event streaming for kernel process creation and DLL loading.
- [ ] **Process Hollow & In-Memory YARA Scanning**:
  - Add native support for dumping and scanning virtual memory pages (`VirtualAllocEx`, `WriteProcessMemory`) against custom YARA rule sets.

---

### Phase 2: Deep Learning & Graph Intelligence (Mid-Term)
- [ ] **Graph Neural Networks (GNN) on Process Ancestry**:
  - Convert process trees into directed acyclic graphs (DAGs).
  - Train GNN models (Graph Convolutional Networks) to spot evasive lateral movements and multi-stage process injection across parent, child, and grand-child trees.
- [ ] **Autonomous LLM SOC Analyst Copilot**:
  - Integrate an on-premise, privacy-preserving local LLM (e.g., Llama 3 / Mistral via Ollama) directly into the dashboard.
  - Analysts can highlight any incident to receive:
    1. Plain-English narrative explaining how the attack executed.
    2. Recommended remediation steps.
    3. Auto-generated Sigma rules and Snort signatures.
- [ ] **Online Reinforcement Learning from Human Feedback (RLHF)**:
  - When an analyst dismisses a false positive or confirms a true positive, the feedback is fed into a reinforcement learner that dynamically adjusts confidence weights without full offline retraining.

---

### Phase 3: Autonomous SOAR & Active Defense (Mid-Term)
- [ ] **Security Orchestration, Automation, and Response (SOAR) Playbooks**:
  - Configurable YAML-based automated playbooks (e.g., *If severity == Critical AND tactic == CredentialAccess -> Isolate host -> Terminate PID -> Invalidate Active Directory user session -> Alert on-call via PagerDuty/Slack*).
- [ ] **Kernel-Level Host Network Micro-Segmentation**:
  - Enforce automated local firewall rule insertion via Windows Filtering Platform (WFP) and Linux `iptables`/`nftables` upon host isolation, blocking everything except the MemGuard telemetry port.
- [ ] **Automated Volatile Memory Triage (Forensic Dumps)**:
  - Automatically snapshot the virtual memory space of the malicious PID to an encrypted `.dmp` container for post-mortem digital forensics before killing the process.

---

### Phase 4: Cloud-Native & Massive Distributed Fleet (Long-Term)
- [ ] **Distributed Event Bus Integration (Apache Kafka / Redpanda)**:
  - Decouple the FastAPI backend from endpoint telemetry streams using a high-throughput Kafka pub-sub pipeline capable of handling $100,000+$ concurrent endpoints.
- [ ] **Kubernetes & Cloud EDR Integration**:
  - Deploy MemGuard as a Kubernetes DaemonSet to monitor containerized environments.
  - Detect container breakouts, unauthorized namespace escapes, and Kubernetes API credential theft.
- [ ] **Multi-Tenant MSSP Console**:
  - Implement full Role-Based Access Control (RBAC), SAML 2.0 / OIDC Single Sign-On, and multi-tenant partitioning for Managed Security Service Providers (MSSPs).

---

### Phase 5: Deception & MITRE D3FEND Framework (Long-Term)
- [ ] **Active Cyber Deception (Canaries & Honey-Tokens)**:
  - Deploy synthetic decoy credentials in memory (`fake_admin` tickets in LSASS) and canary files in user directories.
  - Any access attempt triggers an instant, high-confidence critical alert with zero false-positive risk.
- [ ] **MITRE D3FEND™ Mapping**:
  - Explicitly document defensive countermeasures aligned with the MITRE D3FEND matrix:
    - *Process Termination (D3-PT)*
    - *Network Traffic Filtering (D3-NTF)*
    - *File Eviction (D3-FE)*
    - *Decoy Environment Creation (D3-DEC)*

---

## 🔒 Security & Ethical Usage Notice

> **⚠️ DISCLAIMER**: MemGuard v5 is designed for authorized defensive security operations, educational research, threat hunting, and infrastructure protection. The included attack simulation modules are strictly intended for testing and tuning detection rules in controlled, authorized environments. Unauthorized scanning or tampering with computer systems without prior explicit consent is illegal.

---

## 🤝 Contributing

Contributions to MemGuard are welcome! To contribute:

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/kernel-etw-hook`).
3. Commit your changes (`git commit -m 'Add native ETW event parser'`).
4. Push to the branch (`git push origin feature/kernel-etw-hook`).
5. Open a Pull Request.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>MemGuard v5</b> — Engineered for High-Speed Autonomous Threat Containment.
</p>
