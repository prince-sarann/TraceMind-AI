# Contributing

Thanks for your interest in improving TraceMind AI!

## Before you start

- Check existing issues and pull requests to avoid duplicate work.
- For larger changes, open an issue first to discuss the proposed approach.
- Keep changes focused and explain the reason for them.

## Development setup

1. Fork the repository and clone your fork.
2. Install dependencies with `npm install`.
3. Copy `.env.example` to `.env` and configure the required local secrets.
4. Start the development server with `npm run dev`.

## Before submitting a pull request

Run the checks relevant to your change:

```bash
npm run lint
npm test
npm run build
```

In your pull request:

- Describe what changed and why.
- Include steps to reproduce and verify bug fixes.
- Add or update tests when behaviour changes.
- Include screenshots for meaningful UI changes when possible.
- Do not commit API keys, passwords, private logs, personal information, or real incident data.

## Project principles

- Prefer clear, maintainable TypeScript.
- Keep security findings explainable and grounded in event evidence.
- Distinguish observed facts from model-generated hypotheses.
- Treat AI output as analyst assistance that requires human review.
