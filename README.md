# AURUM-V Merge Gate

[![External installation proof](https://github.com/bradshawdanni-collab/aurum-v-action-demo/actions/workflows/aurum-v-demo.yml/badge.svg)](https://github.com/bradshawdanni-collab/aurum-v-action-demo/actions/workflows/aurum-v-demo.yml)

A fail-closed Docker-based GitHub Action that verifies a signed AURUM-V approval bundle and binds it to the exact repository, pull request and head commit SHA.

**Need implementation support? [Book an AURUM-V Merge Control Pilot](PILOT.md).**

## Quick start

```yaml
name: AURUM-V merge authorization

on:
  pull_request:

jobs:
  verify-approval:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - id: aurum
        uses: bradshawdanni-collab/aurum-v-action@v1.0.0
        with:
          approval-bundle: path/to/signed-approval
          expected-repository: ${{ github.repository }}
          expected-pull-request-number: ${{ github.event.pull_request.number }}
          expected-head-sha: ${{ github.event.pull_request.head.sha }}

      - name: Require verified approval
        shell: bash
        run: test "${{ steps.aurum.outputs.result }}" = "VERIFIED"
```

The approval bundle directory must contain:

```text
approval.json
approval.sig
public_key.pem
SHA256SUMS
```

## External installation proof

A separate public repository installs the Marketplace release exactly as a consumer would, generates an ephemeral demo-only Ed25519 key, verifies a valid signed bundle as `VERIFIED`, then modifies the artifact and confirms the Action fails closed with `TAMPERED`.

- Demo repository: [bradshawdanni-collab/aurum-v-action-demo](https://github.com/bradshawdanni-collab/aurum-v-action-demo)
- Proof workflow: [AURUM-V external installation proof](https://github.com/bradshawdanni-collab/aurum-v-action-demo/actions/workflows/aurum-v-demo.yml)

## Inputs

| Input | Required | Description |
| --- | --- | --- |
| `approval-bundle` | Yes | Path to the signed approval bundle inside the checked-out workspace. |
| `expected-repository` | No | Exact `owner/repository`; defaults to `${{ github.repository }}`. |
| `expected-pull-request-number` | No | Exact pull-request number from the event. |
| `expected-head-sha` | No | Exact pull-request head SHA from the event. |

## Outputs

| Output | Description |
| --- | --- |
| `result` | `VERIFIED`, `REFUSED`, `TAMPERED`, `INVALID_SIGNATURE`, `INVALID_ARTIFACT`, or another controlled verification result. |
| `denial-code` | Controlled reason when authorization is refused. |
| `decision-id` | Identifier from the verified signed decision. |
| `message` | Non-sensitive deterministic result message. |

## Security model

The Action:

- verifies the SHA-256 manifest and Ed25519 detached signature;
- rejects modified artifacts and public-key mismatches;
- refuses signed decisions that are not `APPROVED`;
- binds authorization to the expected repository, pull request and head SHA;
- accepts no GitHub merge credential;
- returns a non-zero exit code for missing, malformed, refused, mismatched, tampered or unverifiable authorization.

It does not replace branch protection or grant merge authority. Protect signing keys, configure required checks, and pin immutable versions where appropriate.

## Version pinning

Use the published release:

```yaml
uses: bradshawdanni-collab/aurum-v-action@v1.0.0
```

Use the major tag for compatible updates:

```yaml
uses: bradshawdanni-collab/aurum-v-action@v1
```

For stricter supply-chain control, pin a full commit SHA.

## Licence and security

Licensed under Apache-2.0. See `LICENSE` and `SECURITY.md`.
