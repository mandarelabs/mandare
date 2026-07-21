# Security Policy

Mandare is security infrastructure; we treat reports accordingly.

## Reporting a vulnerability

Please use **GitHub Private Vulnerability Reporting** on this repository
("Report a vulnerability" under the Security tab). We will:

- acknowledge within 3 business days,
- keep you informed of triage and fix progress,
- credit you in the advisory (GHSA/CVE) unless you prefer otherwise.

Please do not open public issues for suspected vulnerabilities.

## Coordinated disclosure

We follow a **90-day disclosure window**: we aim to ship a fix and publish an
advisory well before the window ends. If a fix needs longer, we will
communicate rather than let the window lapse silently.

## Safe harbor

Good-faith research against your **own deployment** of Mandare is welcome —
including tamper attempts against your own ledger (that is what the red-team
suite does in CI). We will not pursue legal action for good-faith,
non-disruptive research that respects user data and does not target
infrastructure operated by others.

## Scope notes

- The threat model assumes **agent input is hostile** and prompt injection is
  permanent. Reports demonstrating a path from agent-controlled content into
  policy, vault, or ledger-write behavior are the highest-value class.
- A full-machine-root attacker acting entirely outside the doors is outside
  the ledger's claimed coverage (documented boundary; witnessing exists to
  bound it).

## Supply chain

Releases will use npm Trusted Publishing (OIDC) with provenance, signed
containers, and SLSA build attestation. See [REPRODUCING.md](REPRODUCING.md).
