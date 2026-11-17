# TraceMind X

**AI-Powered Cyber Threat Intelligence & Security Incident Investigation Platform**

TraceMind X is a modular Security Operations Center (SOC) investigation platform that ingests and normalizes security logs, detects rule-based threats, correlates multi-stage attack chains using graph algorithms, isolates behavioural outliers via an Isolation Forest ML model, computes explainable risk scores, and delivers evidence-grounded investigation briefings.

## Architecture

```
Security Log Sources (CSV / JSON / Synthetic Corpus)
  └─▶ Log Ingestion & Normalization (validation, deduplication, timestamp/IP normalization)
        ├─▶ Rule-Based Threat Detection Engine (MITRE ATT&CK rules R-001..R-006)
        └─▶ Isolation Forest ML Engine (7 behavioural features, z-score explainability, ROC-AUC/F1)
              └─▶ Graph Event Correlation Engine (BFS connected components, degree centrality)
                    └─▶ Explainable Risk Scoring & Attack Story Builder
                          └─▶ SQLite Persistence (parameterized SQL + audit log)
                                └─▶ Express REST API + Gemini Investigation Assistant
                                      └─▶ Interactive Enterprise SOC Dashboard (9 Views)
```

## Core Capabilities

- **Intelligent Log Ingestion**: Validates `.csv` and `.json`/NDJSON payloads (max 5 MB), normalizes timestamps and event schemas, validates IPv4/IPv6 addresses, deduplicates via SHA-256 fingerprints, and reports rejected lines.
- **Threat Detection Engine**: Configurable detection for brute-force bursts, credential compromise after failures, multi-account password spraying, off-hours privileged access, impossible travel geolocation hops, and privilege escalation + data exfiltration chains.
- **Isolation Forest ML Anomaly Detection**: Subsampled binary space partitioning ensemble computing anomaly scores $s(x, n)$, model evaluation metrics (Precision, Recall, F1, ROC-AUC, Confusion Matrix), and explicit separation between *Behavioural Anomaly (Unconfirmed)* and *Confirmed Malicious*.
- **Graph Correlation & Relationship Explorer**: BFS connected components and interactive pan/zoom network graph linking IPs, accounts, hosts, milestone events, and incidents.
- **Explainable Risk Scoring & Attack Story Builder**: Transparent weighted 0–100 scoring across 5 dimensions and chronological attack timelines grounded strictly in observed events.
- **Evidence-Grounded AI Investigation Assistant**: Server-side `@google/genai` (`gemini-4-hydrogen`) briefings and interactive Q&A citing exact event IDs and separating verified evidence from unverified hypotheses.
- **Incident Management & Reporting**: Persistent SQLite case status, analyst assignment, notes, security audit log, CSV exports, and formatted PDF incident reports.

## Commands

- **Start development server**: `npm run dev`
- **Build production bundle**: `npm run build`
- **Typecheck**: `npm run lint`
- **Run test suite**: `npm test`
