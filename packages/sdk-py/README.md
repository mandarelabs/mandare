# mandare-sdk (Python)

Zero-dependency Python client for a [Mandare](https://github.com/mandarelabs/mandare)
gateway door: scoped-token proof-of-possession auth over the stdlib
(`hmac`, `urllib`) — nothing to audit but this file.

```python
from mandare_sdk import MandareClient, MandareRefused, load_token_file

creds = load_token_file("agent.token.json")  # from `mandare token issue --json`
client = MandareClient("http://127.0.0.1:8484", creds)

try:
    reply = client.messages({
        "model": "claude-haiku-4-5",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": "hello"}],
    })
except MandareRefused as refusal:
    # The door said no — and the refusal itself is a ledger entry.
    print(refusal.code, refusal.denied_entry)
```

**Scope (v0):** token mode and unauthenticated dev mode. Passport mode
(RFC 9421 request signatures) needs Ed25519, which the Python stdlib does not
provide — use the TypeScript SDK (`@mandarelabs/sdk`) for passport-authenticated
agents. Stated here so nobody discovers it the hard way.

Tests: `python3 -m unittest discover -s tests` (run in CI with a pinned
cross-language HMAC vector so this client cannot drift from the vault's wire
encoding).
