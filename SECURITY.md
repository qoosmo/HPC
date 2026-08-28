# Security Policy

## Scope

This repository contains cryptographic research code and deliberately reduced
DES experiments. It is **not production cryptographic software**, has not been
security-audited, and must not be used to protect real data.

DES itself is obsolete. Reporting that DES is insecure is not a vulnerability
in this repository.

## Supported code

Security and correctness fixes target `main` and active pull requests.
Historical artifacts are preserved for provenance and are not maintained as
secure software.

## Sensitive reports

If an issue could expose credentials, private data, a supply-chain weakness, or
a vulnerability in reusable modern code, prefer GitHub private vulnerability
reporting / Security Advisories when available.

Do not publish secrets, credentials, private exploit material, or personal data
in a public issue. If private reporting is unavailable, open a minimal public
issue requesting a private channel without including sensitive details.

Ordinary correctness bugs, benchmark discrepancies, mathematical
counterexamples, and reproducibility failures should use the issue templates.

## Useful report fields

Include the affected commit SHA, toolchain versions, minimal reproduction,
expected/observed behavior, and whether a committed paper claim or benchmark is
affected.
