# Show HN draft — DO NOT POST (S9b runbook item)

Posting logistics (Q29): weekday, ~14:00–16:00 CET (morning US East). Post
from the founder's account. The lead comment goes up immediately after the
submission, from the same account. The founder answers **every** comment for
the first day — the comment thread is the launch. Do not post until every
gate in `LAUNCH-CHECKLIST.md` ahead of the HN step is green.

---

## Title

> Show HN: Mandare – Give your AI agents a budget they can't talk their way out of

(78 chars, fits HN's 80-char limit. Fallback if a mod rewords: "Show HN:
Mandare – signed mandates, tamper-evident ledgers and a kill switch for AI
agents".)

**URL:** https://github.com/mandarelabs/mandare

## Body

I run a small fleet of AI agents for real client work, and the day one of
them got stuck in a loop I realized my "budget control" was a sentence in the
system prompt. Prompts are suggestions. I wanted physics.

Mandare is an accountability stack for agent fleets, local-first and
open source:

- **Mandate** — the human signs machine-readable authority ONCE (€5/call,
  €20/day, ask me above €0.25). No more permission-prompt fatigue; the
  mandate does the saying-no.
- **Gateway** — your agent's existing Anthropic/OpenAI SDK just changes its
  base URL. Every call: policy check → INTENT entry (reserves the estimated
  cost inside the ledger transaction) → provider → RESULT entry (settles the
  true cost). Overshoot is prevented by construction — a reservation race
  can't pierce the cap, and there's a red-team test in CI that proves it.
- **Ledger** — append-only, hash-chained, door-signed, RFC 6962 tree.
  Refusals are recorded too: the system keeps its no's.
- **Kill switch** — `mandare kill <agent>` is a local, offline operation.
  A kill that needs a cloud round-trip is a kill that can be jammed.
- **Witnessing** — heads stream to an external witness (salted 32-byte
  roots, zero content), so even the key-holding operator can't truncate or
  rewrite history undetected. Aggregate roots anchor via OpenTimestamps.
- **Card rail** — the same mandate governs a Stripe Issuing virtual card;
  the decline happens at the card network, in the authorization webhook,
  before the merchant sees an approval. One cap across LLM + card spend.

Try it with no API keys (mock provider, real enforcement):

    git clone https://github.com/mandarelabs/mandare && cd mandare
    docker compose up -d --wait
    docker compose run --rm demo

That releases an actual runaway loop against your own gateway and shows it
dying at call #72, then proves the ledger. The five demos in `examples/` are
the CI acceptance tests — if the README claim and the test disagree, the
test wins.

Stack: TypeScript, Fastify, SQLite/Postgres, Ed25519 throughout; passports
are did:key + SD-JWT VCs, requests are RFC 9421-signed with Content-Digest.
The verification side (verifier, passport, witness protocol) is Apache-2.0
and embeddable; the doors are AGPL. More on the licensing split and the
threat model in my first comment.

Solo founder, pre-revenue, this is launch day. I'd especially value scrutiny
of the threat model — the security review doc lists what an external auditor
should attack first, and I'll be in the comments all day.

## Lead comment (post immediately after submission)

A few things HN will (rightly) want to know:

**Why AGPL + Apache split?** Grafana pattern. Everything a *distrusting
third party* must run to check our claims is Apache-2.0 and dependency-light:
the spec, the chain/proof verifier, the passport verification, the witness
protocol, the SDKs. You should never have to trust — or even run — our
code to verify our ledgers. The doors (gateway, card rail, vault, MCP
server, dashboard) are AGPL-3.0-only: self-host freely; if you offer them
as a service, share your changes. The split is permanent and documented in
LICENSING.md; we don't do rug-pull relicensing.

**Threat model, honestly.** What it defends against: a compromised or
prompt-injected agent (input is assumed hostile — schema-validated,
allowlisted operations only), stolen credentials (vault + proof-of-
possession tokens; agents never hold raw provider keys), a runaway loop
(reservation inside the ledger's write transaction), retroactive
tampering (hash chain + external witnessing + public anchoring), and "the
card already went through" (authorization-time decline at the network).

What it does NOT defend against, listed in the docs and repeated here so
nobody has to dig: (1) a full-root attacker acting entirely *outside*
Mandare's doors — we're the seatbelt on the doors, not a hypervisor;
(2) in the single-host solo compose stack, the witness shares the machine,
so a full-root operator can rewrite both sides consistently — team mode or
a second host closes this, and the docs say so on the front page, not in a
footnote; (3) self-anchored verification (no witness) proves consistency,
not authorship.

**The pre-launch review.** Before going public, four independent adversarial
review passes (crypto/integrity, spend/enforcement, packaging/supply-chain,
docs-vs-claims) produced 15 findings — 3 HIGH, including a certificate
key-binding gap and a token-estimation bound that under-reserved CJK input
~3x. All fixed with regression tests that fail on the pre-fix code, or
documented as accepted residuals. The full report, including what was probed
and held and the target list we're handing the external auditor, is in the
repo: docs/SECURITY-REVIEW-S8.md. The red-team suites (tamper, replay,
forgery, budget races, witness split-view) run in CI on every push, on
SQLite and Postgres, and the rule is they may never be weakened to make a
change pass.

**Supply chain**: no install scripts (pnpm 10), 3-day cooldown on new
dependency versions, frozen lockfiles, npm Trusted Publishing with
provenance from day one, cosign-signed images, and the OpenClaw skill ships
in a signed envelope whose verifier fails closed on unsigned/unpinned
packages. One dependency we'll flag ourselves: web-bot-auth (RFC 9421
plumbing) is pre-1.0 and unaudited — it's pinned exact, we layer our own
component/nonce/digest enforcement on top, and it's first on the external
audit list.

Ask me anything, including the uncomfortable ones.

---

## Prepared answers for predictable questions (not part of the post)

- **"Why not just use provider spend limits?"** Provider caps are per-key,
  per-provider, eventually-consistent, and say nothing about *which agent*
  spent it or *whether it was authorized*. Mandare is per-mandate, cross-
  provider, cross-rail (LLM + card), attributable, and produces evidence.
- **"Why not LiteLLM/Portkey/Helicone?"** Those are gateways/observability —
  great at seeing spend. Mandare is enforcement + evidence: signed authority
  in, tamper-evident proof out, fail-closed in between. We'd rather
  integrate with their telemetry than compete with it.
- **"AGPL is a virus / dealbreaker."** The parts you embed are Apache. The
  AGPL parts are servers you self-host; AGPL obligations trigger on
  *offering them as a service*, not on using them internally. If you're a
  cloud reselling the door, yes — we want your changes back.
- **"Blockchain?"** No token, no chain of ours. OpenTimestamps commits hashes
  to Bitcoin as a public timestamping notary; nothing else touches a chain,
  and the system is fully functional without it.
- **"What about the OpenClaw skill?"** Ships after its third-party audit,
  not with the initial launch — a skill is agent-executed instructions, so
  it gets the highest bar, not the lowest.
- **"Does the witness see my prompts?"** No — sizes and salted 32-byte tree
  roots only. Selective-disclosure certificates let you prove specific
  entries to a third party without opening the rest.
