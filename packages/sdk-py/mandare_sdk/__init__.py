"""Python client for the Mandare gateway.

Scope (v0): the S3 scoped-token proof-of-possession auth mode and
unauthenticated dev mode, over stdlib only — no dependencies to audit
(hmac, hashlib, urllib, json, secrets). Passport mode (RFC 9421 request
signatures) needs Ed25519, which the stdlib does not provide; use the
TypeScript SDK (@mandarelabs/sdk) for passport-authenticated agents, or
terminate passports elsewhere. This asymmetry is documented, not hidden.

WIRE CONTRACT (shared with @mandarelabs/vault): the agent presents four
headers; the proof is HMAC-SHA256 over a newline-joined preimage
``token_id\\nMETHOD\\npath\\ntimestamp\\nnonce`` keyed by the per-token
secret, base64url without padding. The cross-language pinned vector in
``tests/test_client.py`` fails if either side drifts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

__all__ = [
    "TOKEN_HEADER",
    "TIMESTAMP_HEADER",
    "NONCE_HEADER",
    "POP_HEADER",
    "TokenCredentials",
    "MandareRefused",
    "MandareClient",
    "pop_preimage",
    "pop_proof",
    "token_auth_headers",
    "load_token_file",
]

TOKEN_HEADER = "x-mandare-token"
TIMESTAMP_HEADER = "x-mandare-timestamp"
NONCE_HEADER = "x-mandare-nonce"
POP_HEADER = "x-mandare-pop"


@dataclass(frozen=True)
class TokenCredentials:
    """A scoped token grant: public id + the secret revealed once at mint."""

    token_id: str
    pop_secret: str


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pop_preimage(
    token_id: str, method: str, path: str, timestamp: str, nonce: str
) -> str:
    """The exact bytes both sides HMAC - one canonical preimage."""
    return "\n".join([token_id, method.upper(), path, timestamp, nonce])


def pop_proof(
    pop_secret: str, token_id: str, method: str, path: str, timestamp: str, nonce: str
) -> str:
    """HMAC-SHA256(pop_secret, preimage), base64url - the vault's encoding."""
    digest = hmac.new(
        pop_secret.encode("utf-8"),
        pop_preimage(token_id, method, path, timestamp, nonce).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url(digest)


def _utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def token_auth_headers(
    credentials: TokenCredentials,
    method: str,
    path: str,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """The four headers a Mandare door requires in token auth mode.

    ``path`` is signed WITHOUT a query string (door parity); each call gets a
    fresh single-use nonce unless one is injected for tests.
    """
    clean_path = path.split("?", 1)[0]
    stamp = timestamp if timestamp is not None else _utc_now_iso()
    use_nonce = nonce if nonce is not None else _b64url(secrets.token_bytes(18))
    return {
        TOKEN_HEADER: credentials.token_id,
        TIMESTAMP_HEADER: stamp,
        NONCE_HEADER: use_nonce,
        POP_HEADER: pop_proof(
            credentials.pop_secret,
            credentials.token_id,
            method,
            clean_path,
            stamp,
            use_nonce,
        ),
    }


def load_token_file(path: str) -> TokenCredentials:
    """Load a token grant file: the JSON ``mandare token issue --json``
    prints, saved to a 0600 file (the Mandare MCP server writes exactly
    that; from the CLI, redirect stdout yourself)."""
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    token_id = raw.get("token_id")
    pop_secret = raw.get("pop_secret")
    if not isinstance(token_id, str) or not isinstance(pop_secret, str):
        raise ValueError(f"{path} is not a mandare token grant (token_id, pop_secret)")
    return TokenCredentials(token_id=token_id, pop_secret=pop_secret)


class MandareRefused(Exception):
    """The door said no. The refusal itself is a ledger entry."""

    def __init__(
        self, status: int, code: str, reasons: list[str], denied_entry: str | None
    ) -> None:
        super().__init__(f"mandare door refused ({code}): {'; '.join(reasons)}")
        self.status = status
        self.code = code
        self.reasons = reasons
        self.denied_entry = denied_entry


class MandareClient:
    """Minimal client for a Mandare gateway door.

    >>> client = MandareClient("http://127.0.0.1:8484", credentials)
    >>> client.messages({"model": "claude-haiku-4-5", "max_tokens": 64,
    ...                  "messages": [{"role": "user", "content": "hi"}]})

    A door refusal raises :class:`MandareRefused` with the code and the
    ledger entry hash of the recorded refusal.
    """

    def __init__(
        self,
        base_url: str,
        credentials: TokenCredentials | None = None,
        timeout_seconds: float = 120.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.credentials = credentials
        self.timeout_seconds = timeout_seconds

    def post_json(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        payload = json.dumps(body).encode("utf-8")
        headers = {"content-type": "application/json"}
        if self.credentials is not None:
            headers.update(token_auth_headers(self.credentials, "POST", path))
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=payload, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            raw = error.read().decode("utf-8", errors="replace")
            if error.code in (401, 403):
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    parsed = {}
                if isinstance(parsed.get("code"), str):
                    raise MandareRefused(
                        status=error.code,
                        code=parsed["code"],
                        reasons=[r for r in parsed.get("reasons", []) if isinstance(r, str)]
                        or [parsed.get("reason", "")],
                        denied_entry=parsed.get("denied_entry"),
                    ) from None
            raise RuntimeError(f"gateway {path} returned {error.code}: {raw}") from None

    def messages(self, body: Mapping[str, Any]) -> dict[str, Any]:
        """Anthropic-native door route."""
        return self.post_json("/v1/messages", body)

    def chat_completions(self, body: Mapping[str, Any]) -> dict[str, Any]:
        """OpenAI/OpenRouter-native door route."""
        return self.post_json("/v1/chat/completions", body)
