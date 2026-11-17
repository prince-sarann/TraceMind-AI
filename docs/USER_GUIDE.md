# TraceMind AI — Analyst User Guide

This guide explains how to run the educational SOC workspace and practise a repeatable investigation workflow. All bundled events are synthetic. Do not upload real customer telemetry or confidential incident records.

## 1. Start the application

1. Install Node.js 22.12 or newer and Bun.
2. Clone the repository and install dependencies:

   ```bash
   git clone https://github.com/prince-sarann/TraceMind-AI.git
   cd TraceMind-AI
   bun install --frozen-lockfile
   ```

3. Copy `.env.example` to `.env`. Add your own `GEMINI_API_KEY` locally if you want to use AI features. Never commit `.env`.
4. Start the app with `bun run dev` and open [http://localhost:3000](http://localhost:3000).

On first launch, TraceMind creates a local SQLite database and seeds it with synthetic events. The database is stored in `.data/` and is intentionally excluded from Git.

## 2. Understand the workspace

### Security Overview

Start here. Review the event count, flagged events, incident severity distribution, trend chart, geographic telemetry, and incident queue. These are calculations from the dataset loaded into this local demo—not a live feed from your organisation.

### Log Explorer

Use this screen to inspect normalized events.

- Search by event ID, IP address, username, host, country, city, or ASN.
- Narrow results by severity and event type; use the IP and user filters for focused triage.
- Sort by event time, IP reputation, or bytes transferred.
- Select **Ingest Logs**, then load the bundled sample CSV or choose a CSV/JSON file.
- Review accepted, duplicate, and rejected record counts after ingestion. Rejected records include sample reasons to help fix source data.

The upload limit is 5 MB. The parser expects recognizable timestamps, IP addresses, usernames, and supported event types. An uploaded record is not automatically malicious just because it was accepted.

### Threat Detection

Review deterministic rule hits separately from behavioural anomalies.

- Rule hits explain which configured heuristic matched and show its supporting events.
- An anomaly is an unusual pattern, not proof of malicious activity.
- A **Confirmed Malicious** classification in this demo means the event/entity matched the configured rule evidence; it is not a real-world verdict.
- Check the evidence, time window, affected accounts, and MITRE ATT&CK mapping before drawing conclusions.

### Security Incidents

Choose an incident from the queue to inspect its severity, risk score, narrative, affected entities, matched events, and notes.

1. Open the incident and verify its evidence.
2. Assign an analyst and update the status as the investigation progresses.
3. Add concise notes containing observations, timestamps, and next actions.
4. Use the AI briefing as a starting point, then compare every important claim with the underlying events.

A risk score is a prioritization aid, not a probability that an attack succeeded.

### Attack Timeline and Threat Intelligence Graph

Use the timeline to review the sequence of events. Use the relationship graph to explore connections between IPs, accounts, hosts, and events. A graph edge indicates a relationship created by the demo correlation logic; it does not independently prove causation.

### AI Assistant

Select an incident and request an investigation brief, or ask a question about the loaded telemetry. Useful questions include:

- “Which events support this incident, and what are their timestamps?”
- “What evidence would help confirm or disprove the suspected account compromise?”
- “What should an analyst validate before containment?”
- “Separate observed facts from hypotheses.”

AI output can be wrong or incomplete. Validate claims against the original log records. AI features require a working Gemini API key; other dashboard features can be explored without it.

### Analytics and Reports

Export normalized events or incidents as CSV, or generate a PDF case report. Treat exported files as sensitive if you have added non-synthetic data. Keep them out of public repositories.

### Settings and About

Adjust detection thresholds and save to recompute the pipeline. Use **Reset Synthetic Dataset** only when you intend to discard imported logs, incident statuses, and analyst notes. The app asks for confirmation before resetting.

The analyst name and role selector are for demonstration only. They are sent as client-provided headers and are not real login credentials or secure role-based access control.

## 3. Practice a complete investigation

Use this repeatable learning exercise with the bundled synthetic dataset:

1. **Triage:** On Security Overview, identify the highest-severity incident and note its risk score.
2. **Scope:** Open the incident. Record the primary IP, affected users, hosts, and time window.
3. **Validate:** Open the matched events. Confirm the sequence and distinguish failed logins from successful logins, privilege changes, and data exports.
4. **Correlate:** Review the attack timeline and graph. Note which relationships are supported by shared identifiers or time proximity.
5. **Assess:** Review rule hits, anomaly details, and risk factors. Do not treat an anomaly score alone as proof.
6. **Document:** Add an investigation note that states the evidence, uncertainty, and next verification step.
7. **Respond (simulation):** Update the incident status and assignee to practise the case workflow. No real account or network is contained by this demo.
8. **Report:** Export a case PDF and review the audit log entry.

## 4. Troubleshooting

| Symptom | What to check |
| --- | --- |
| Dashboard does not load | Confirm `bun run dev` is running and retry the page. |
| AI feature returns a missing-key error | Add `GEMINI_API_KEY` to your local `.env` and restart the server. |
| Upload rejects records | Check timestamp format, valid IP address, username, and supported event type. |
| Duplicate count increases | The importer uses event fingerprints to avoid inserting the same normalized event twice. |
| Layout looks cramped | Test at 360 px, 768 px, and 1440 px; tables may scroll horizontally inside their own panels. |
| Settings do not save | Check the server terminal for API errors and verify that the simulated Lead SOC Analyst role is selected. |

## 5. Important limitations

TraceMind AI is an educational portfolio project, not a production SIEM or incident-response platform. It does not collect live telemetry, authenticate users, enforce secure multi-user authorization, or perform containment actions. Use synthetic data only, and never expose an unauthenticated deployment to untrusted users.
