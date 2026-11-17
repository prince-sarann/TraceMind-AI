# TraceMind AI

**AI-assisted security incident investigation platform for SOC workflows.**

TraceMind AI is a modular Security Operations Center (SOC) investigation workspace. It brings security-log ingestion, threat detection, event correlation, anomaly analysis, explainable risk scoring, attack timelines, and AI-assisted investigation into one dashboard.

Built as a portfolio and learning project by **Prince Kumar Saran**.

> **Project status:** Educational / portfolio project. The repository includes synthetic sample data. Detection results and AI-generated explanations are decision-support signals—not proof of compromise. Always validate findings against original evidence.

## Highlights

- **Log ingestion and normalization** — accepts CSV and JSON/NDJSON event data, validates records, normalizes fields, and reports rejected rows.
- **Rule-based threat detection** — identifies suspicious patterns such as repeated authentication failures, password spraying, unusual privileged access, and related event sequences.
- **Anomaly analysis** — uses an Isolation Forest-style model to highlight unusual behaviour and keeps unconfirmed anomalies distinct from confirmed malicious activity.
- **Event correlation** — connects related users, hosts, IP addresses, and events to help analysts investigate possible attack chains.
- **Explainable risk scoring** — provides a risk score with contributing factors rather than relying on an unexplained label.
- **Attack timelines and investigation stories** — organizes observed events chronologically to support incident review.
- **AI investigation assistant** — uses the Google Gemini API for evidence-oriented summaries and investigation assistance.
- **Incident workflow and reporting** — supports case information, analyst notes, audit history, exports, and reports.

## Technology

| Area | Technologies |
| --- | --- |
| Frontend | React, TypeScript, Vite |
| Backend | Node.js, Express |
| Data storage | SQLite via sql.js |
| AI integration | Google Gemini API (@google/genai) |
| Visualization | Chart and network-graph components |
| Testing | Vitest, TypeScript |

## Architecture

```text
CSV / JSON / synthetic security events
                |
                v
       Ingestion & normalization
                |
        +-------+--------+
        |                |
        v                v
 Rule-based detection  Anomaly analysis
        |                |
        +-------+--------+
                |
                v
       Event correlation
                |
                v
       Risk scoring & timeline
                |
                v
        SQLite persistence
                |
                v
      Express API + Gemini AI
                |
                v
        SOC investigation UI
```

## Getting started

### Prerequisites

- Node.js 22.12 or newer
- [Bun](https://bun.sh/) (the repository includes a Bun lockfile)
- A Google Gemini API key for AI-assisted features

### 1. Clone the repository

```bash
git clone https://github.com/prince-sarann/TraceMind-AI.git
cd TraceMind-AI
```

### 2. Install dependencies

```bash
bun install --frozen-lockfile
```

### 3. Configure environment variables

Create a local environment file from the example:

```bash
cp .env.example .env
```

Open `.env` and add your own Gemini API key:

```env
GEMINI_API_KEY=your_gemini_api_key
```

Keep real credentials in your local `.env` file or your deployment platform's secret manager. **Never commit API keys, tokens, passwords, or production data.** The `.env.example` file contains placeholders only.

### 4. Start the development server

```bash
bun run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## Available scripts

| Command | Description |
| --- | --- |
| `bun run dev` | Start the Express server with Vite development middleware |
| `bun run build` | Build the frontend for production |
| `bun run preview` | Preview the Vite production build |
| `bun run lint` | Run the TypeScript type check |
| `bun run test` | Run the automated test suite |
| `bun run start` | Start the application server |

## Project structure

```text
TraceMind-AI/
├── src/
│   ├── components/     # Reusable UI, charts, and SOC components
│   ├── lib/            # Frontend API helpers
│   ├── views/          # Dashboard and investigation screens
│   ├── App.tsx         # Main application component
│   └── index.css       # Global styles
├── server/
│   ├── data/           # Synthetic sample dataset
│   ├── db/             # Database access and persistence
│   ├── engine/         # Detection, correlation, scoring, and analysis
│   └── routes/         # API endpoints
├── shared/             # Shared TypeScript types
├── tests/              # Automated tests
├── .env.example        # Environment variable template
├── server.ts           # Application server entry point
└── package.json        # Dependencies and scripts
```

## Security and data handling

- **Demo authentication only:** analyst names and roles are supplied by client request headers in this learning build. They are not authenticated identities, so role selection is not an authorization boundary. Do not expose this app to untrusted users or use it to protect real incident data without adding server-side authentication, authorization, and deployment hardening.
- Use synthetic or properly anonymized events for demonstrations.
- Do not upload real customer logs, credentials, personal information, or production incident data.
- Keep `.env` and all secret-bearing files out of version control.
- Treat AI-generated summaries and anomaly scores as analyst assistance; verify them against source events.
- Report suspected security issues privately to the repository owner rather than posting sensitive details in a public issue.

## Limitations

TraceMind AI is a learning and portfolio project, not a production SIEM or a replacement for an organization's incident-response process. Detection quality depends on input data, configured rules, and model assumptions. AI output can be incomplete or incorrect and must be reviewed by a human analyst.

## Quality checks

A GitHub Actions workflow runs the TypeScript check, automated tests, and production build on pushes and pull requests targeting `main`.

## Security

Read [SECURITY.md](SECURITY.md) before testing or deploying the project. Analyst roles in this educational build are simulated through client-provided headers; they are not real authentication or authorization.

## Contributing

Contributions, bug reports, and suggestions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## Author

**Prince Kumar Saran**  
Creator and developer of TraceMind AI.

- GitHub: [@prince-sarann](https://github.com/prince-sarann)

---

If you find the project useful, consider giving the repository a ⭐.
