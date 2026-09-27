# @mandarelabs/mcp-server (AGPL-3.0-only)

The door as MCP tools (Q17): a **stdio** server any MCP host (Claude Code /
Desktop, agent frameworks) can spawn. It is deliberately a THIN ADAPTER over
the `mandare` CLI — the CLI is the local authority surface, and one code path
beats two.

Rules here:

- **R4:** the model never chooses paths or vault settings — ledger DB, home
  dir, witness, and gateway URL come exclusively from the operator's env in
  the MCP host config. Tool args are zod-validated and passed as discrete
  argv entries (no shell).
- **R2:** issuance results reference secrets BY PATH (0600 grant files in
  `MANDARE_MCP_HOME`); `pop_secret`/private JWKs never enter model context.
  `redactSecrets` is the belt on top.
- **Kill is always on; reinstate is opt-in** (`MANDARE_MCP_ALLOW_REINSTATE=1`)
  — a TOOL-SURFACE restriction only. The server runs with operator-level
  door access (kill/issuance sign with the door key), so code running in its
  environment can reinstate directly; never document it as a key boundary
  (S10-fix K-1).
- `server.json` is the MCP-registry manifest (namespace `com.mandarelabs`,
  DNS-verified against mandarelabs.com at launch). It is PREPARED but not
  published until S9 — the repo is private; publishing is a launch act.
- Tests pair client+server over `InMemoryTransport` and, for the E2E, spawn a
  REAL gateway: MCP kill must close a live door.
