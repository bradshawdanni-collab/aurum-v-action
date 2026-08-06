# Security Policy

## Supported versions

Security fixes are provided for the current major release line.

| Version | Supported |
| --- | --- |
| `v1` | Yes |
| `< v1` | No |

## Reporting a vulnerability

Do not open a public issue for suspected vulnerabilities involving signature verification, authorization bypass, tamper detection, replay handling, repository or commit binding, or credential exposure.

Use GitHub private vulnerability reporting for this repository. Include the affected version or commit, exact reproduction steps, expected and observed behavior, sanitized logs, and whether authorization could be bypassed or evidence altered.

Confirmed issues are handled with a fail-closed default. Affected releases may be withdrawn or marked unsupported until a corrected version is available.

## Security boundaries

AURUM-V verifies signed authorization evidence. It does not grant merge authority, hold GitHub merge credentials, or replace repository branch protection. Consumers remain responsible for protecting signing keys, configuring branch protection and required checks, preventing untrusted approval-bundle modification, and reviewing Action updates before changing version pins.

Never commit private signing keys, access tokens, `.env` files, customer evidence, or production approval bundles.
