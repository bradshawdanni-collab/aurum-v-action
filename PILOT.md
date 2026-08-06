# AURUM-V Merge Control Pilot

A fixed-scope implementation package for teams that need stronger control over merge authorization, tamper evidence, and auditability in GitHub.

## The problem

GitHub branch protection and required checks help control merges, but they do not by themselves prove that a specific approval decision was signed, bound to the exact repository, pull request, and head commit SHA, and remained unchanged before execution.

AURUM-V adds a fail-closed verification layer that checks signed authorization evidence before downstream merge or deployment steps proceed.

## The outcome

At the end of the pilot, one selected GitHub repository will have:

- AURUM-V Merge Gate installed;
- one signed approval policy implemented;
- repository, pull-request, and head-SHA binding configured;
- a demonstrated valid authorization path;
- a demonstrated tamper/fail-closed path;
- handover documentation for the team.

## Included

- Review of one GitHub repository and its current merge workflow
- Installation of the AURUM-V Merge Gate GitHub Action
- Configuration of one signed approval workflow
- Exact repository, pull-request, and head-SHA binding
- Tamper and fail-closed demonstration
- Handover documentation
- 30 days of post-delivery support

## Excluded

- Multi-repository rollout
- More than one approval policy
- Hosted signing infrastructure
- Custom dashboards or compliance reporting
- Enterprise identity-provider integration
- Ongoing managed operations beyond the 30-day support period
- Remediation of unrelated repository or application-security issues

Additional work can be quoted separately after the pilot.

## Delivery

Delivered within 5 business days after repository access and requirements are confirmed.

## Price

**A$1,500 fixed**

The price covers one repository and one approval policy.

## What the client provides

- Access to the selected GitHub repository
- A technical contact who can confirm the intended approval rule
- Availability to review the final demonstration and handover

## Contact

To discuss scope or request a pilot, open a GitHub issue in this repository with the title:

`AURUM-V Pilot Enquiry`

Do not include credentials, private keys, sensitive repository details, or confidential information in a public issue. Sensitive details can be exchanged through an agreed private channel after initial contact.

## Book an AURUM-V Merge Control Pilot

Start with one repository, one policy, and a complete fail-closed authorization demonstration.
