# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security
Advisories ("Report a vulnerability" on the repository) or by email to the
maintainer. Do not open public issues for security reports.

You can expect an acknowledgement within 72 hours. Please include steps to
reproduce and an impact assessment if you can.

## Scope

The Sunder service, its CLI subcommands, and the official SDKs. Findings in
dependencies should go to the upstream project, but a heads-up is welcome.

## Supported versions

Pre-1.0: only the latest release receives fixes.

## Design notes for researchers

The design (full detail in docs/DESIGN.md):

- Search tokens are keyed HMAC-SHA256, keys held outside the database.
- OTIs are PASETO v4.public, single-use enforced by an atomic DB transition.
- The audit log is an append-only hash chain anchored to an RFC 3161 TSA.
- Interesting attack surfaces: lookup enumeration, purpose-check bypasses,
  replay of OTIs across audiences, timing side channels in token compare.
