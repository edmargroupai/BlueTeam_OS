# Secrets policy

- Never commit `.env`, keys, tokens, or PEM material
- Rotate any value that appears in logs or tickets
- Dev passwords exist only under `BTOS_DEV_PASSWORD` and are disabled when `BTOS_ENV=production`
- API keys are stored as SHA-256 hashes
- CI runs gitleaks; a secret finding blocks production promotion
