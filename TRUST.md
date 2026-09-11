# ELLOXA Merge Control — Trust & Evidence

This page separates what can be inspected or reproduced today from what is still pending independent establishment.

## What is publicly inspectable

### Public verification Action

The implementation in this repository is the public AURUM-V Merge Gate distribution used by the ELLOXA Merge Control Pilot.

It verifies signed approval evidence and binds authorization to the expected:

- repository;
- pull request number; and
- exact head commit SHA.

It fails closed for missing, malformed, refused, mismatched, tampered, or unverifiable authorization evidence.

The Action does not grant merge credentials and does not replace GitHub branch protection.

### External installation proof

A separate public consumer repository installs the published Action, generates an ephemeral demo-only signing key in the GitHub runner, verifies a valid approval bundle, then modifies the signed artifact and requires the tampered path to fail.

- Demo repository: https://github.com/bradshawdanni-collab/aurum-v-action-demo
- Proof workflow: https://github.com/bradshawdanni-collab/aurum-v-action-demo/actions/workflows/aurum-v-demo.yml

No private production key is required for that demonstration.

### Repository CI

This repository maintains automated smoke and integrity checks around the public Action and its frozen recovery-specification evidence. Passing repository CI supports the bounded claim that the checked code and declared evidence satisfy those repository-local checks; it is not a universal production certification.

## Independent evidence status

A bounded independent Step-7 replay has been requested from a third-party developer:

- Reviewer request: https://github.com/bradshawdanni-collab/aurum-v-action/issues/3
- Canonical attestation template: [STEP7_ATTESTATION_TEMPLATE.md](STEP7_ATTESTATION_TEMPLATE.md)

Current public status:

```text
Step7IndependentReviewer = NOT_ESTABLISHED
```

Until a qualifying independent reviewer performs the replay and submits a valid attestation, ELLOXA/AURUM-V should not claim that this independent-review condition has been satisfied.

## What the public evidence does not establish

The public implementation, demo, CI results, and any future bounded replay do not by themselves establish:

- universal correctness;
- legal or regulatory compliance;
- production fitness for every deployment;
- secure custody of a customer's signing keys;
- correct configuration of a customer's branch protection;
- absence of every possible bypass outside the verified path; or
- independent certification beyond the exact scope of an attestation.

## What a buyer can verify before engaging

1. Inspect the Action source and security model in this repository.
2. Inspect or run the external installation proof.
3. Review the exact scope and price in [PILOT.md](PILOT.md).
4. Check the independent-review issue for the current attestation state.
5. Open a non-sensitive commercial enquiry only when the evidence boundary is acceptable.

## Start an enquiry

[Open an ELLOXA commercial enquiry](https://github.com/bradshawdanni-collab/aurum-v-action/issues/new?template=commercial-enquiry.md)

Do not post credentials, private keys, confidential repository details, customer data, or unpublished vulnerabilities in a public issue. Sensitive scope is handled only after a private channel is agreed.
