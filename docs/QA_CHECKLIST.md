# Manual QA Checklist

Use this checklist after changes to the interface or investigation workflow. Automated CI checks TypeScript, unit tests, and the production build; it does not replace browser testing.

## Responsive layout

- [ ] 360 px wide phone: navigation drawer opens/closes; no page-level horizontal overflow.
- [ ] 360 px wide phone: dashboard cards stack; long titles, IPs, and usernames wrap or truncate safely.
- [ ] 360 px wide phone: log, detection, incident, and audit tables scroll inside their own panels.
- [ ] 360 px wide phone: ingest modal fits the viewport and text inputs remain usable.
- [ ] 768 px tablet: navigation, cards, charts, and forms reflow without overlapping.
- [ ] 1440 px desktop: sidebar collapse/expand works and content remains readable.
- [ ] Keyboard: tab order is visible; Escape closes the mobile navigation drawer and dialogs where supported.

## Core workflow

- [ ] First launch seeds the synthetic dataset and loads the overview.
- [ ] Refresh/recompute reloads the workspace without duplicate events.
- [ ] Log Explorer search, filters, sorting, pagination, and CSV export work.
- [ ] Sample CSV ingestion reports accepted, duplicate, and rejected records accurately.
- [ ] JSON ingestion accepts valid records and reports malformed records.
- [ ] Threat Detection displays rule evidence and anomaly details.
- [ ] Incident status and assignee updates persist after refresh.
- [ ] Analyst notes persist after refresh.
- [ ] Attack Timeline and relationship graph load for selected incidents.
- [ ] AI briefing and Copilot work when a valid Gemini key is configured; missing-key errors are clear otherwise.
- [ ] CSV and PDF reports download with TraceMind AI branding.
- [ ] Settings save and recompute; reset requires confirmation and restores the synthetic baseline.

## Security and data hygiene

- [ ] No API keys, tokens, passwords, or private logs are committed.
- [ ] `.env` and local `.data/*.sqlite` files remain ignored by Git.
- [ ] CSV exports neutralize spreadsheet formula prefixes.
- [ ] Demo analyst role selection is not presented as production authentication.
- [ ] Only synthetic or properly anonymized data is used during testing.
