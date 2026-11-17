# Security Policy

## Intended use

TraceMind AI is an educational and portfolio project. It is not a production SIEM, incident-response platform, or authenticated multi-user security product.

The current analyst identity and role values are supplied by client request headers. They are useful for demonstrating UI workflows only and must not be treated as real authentication or authorization.

## Reporting a vulnerability

Please do not publish API keys, credentials, private logs, personal information, or exploit details in a public issue.

If GitHub private vulnerability reporting is enabled for this repository, use the **Security** tab to report a vulnerability privately. Otherwise, contact the repository owner through their GitHub profile and request a private channel.

## Safe testing

- Use synthetic or properly anonymized security events.
- Never commit secrets or production telemetry.
- Keep Gemini API keys in local environment variables or a deployment secret manager.
- Do not expose an unauthenticated deployment to untrusted networks.
