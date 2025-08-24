# AlynCoin Security Baseline (Milestone 0)

## Keys & KDF
- All private keys (RSA, Dilithium, Falcon) must be encrypted at rest with Argon2id-derived keys.
- Two KDF profiles:
  - Interactive: ~250–500 ms, ≈256 MiB memory
  - Sensitive: ~500–1200 ms, ≈512 MiB memory
- Unique 16-byte salt per wallet; 32-byte derived key; secure random nonces.

## AEAD
- XChaCha20-Poly1305 for envelope encryption.
- Header includes: version, salt, profile, mem/time params, nonce, alg id.
- Decrypt-on-use only; zeroize plaintext ASAP.

## Passphrases
- Min length 12; warn on weak entropy.
- Optional breach-list check (disabled by default in M0).

## TOTP (optional 2FA)
- RFC-6238, SHA-1, 6 digits, 30s period, ±1 step drift.
- Store secrets encrypted; display `otpauth://` URI + QR on setup.

## Secrets Management
- Secrets never in logs or code; use a secret store.
- Env vars only for non-secrets; redact by default.

## Release Integrity
- Sign tags and/or artifacts (GPG or Cosign).
- Publish checksums and SBOM/provenance with releases.

## Logging
- Structured JSON logs; no secrets; redact patterns.
- Include: timestamp, level, module, event, error, trace id.

## Threat Model (v1)
- Adversaries: local malware, RPC MITM, key exfiltration, mempool frontrun, relayer/bridge compromise.
- Near-term mitigations: at-rest encryption, TOTP, spend policies, commit-reveal mempool, relayer rate-limits.

## Incident Response
- Contact: security@alyncoin.example (update when ready)
- Triage windows: Critical < 24h, High < 72h.
- Public advisories for high/critical issues post-fix.
