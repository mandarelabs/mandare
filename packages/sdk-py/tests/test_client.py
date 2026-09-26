"""Wire-contract tests for the Python client.

The pinned vector below was produced by the reference implementation
(@mandarelabs/vault, node:crypto HMAC-SHA256 base64url). The same vector is
pinned on the TypeScript side — if either language drifts from the vault
encoding, its copy of this test fails.
"""

import unittest

from mandare_sdk import (
    TokenCredentials,
    pop_preimage,
    pop_proof,
    token_auth_headers,
)

PINNED = {
    "token_id": "tok_abc123",
    "method": "post",
    "path": "/v1/messages",
    "timestamp": "2026-08-09T12:00:00.000Z",
    "nonce": "nonce-1",
    "secret": "s3cret",
    # node:crypto: createHmac('sha256','s3cret').update(preimage).digest('base64url')
    "proof": "K6jPOJk3fZ43vUqSNvIGnrX0Jn-erMclkvHf8YhvZgE",
}


class PreimageTest(unittest.TestCase):
    def test_canonical_preimage(self) -> None:
        self.assertEqual(
            pop_preimage(
                PINNED["token_id"],
                PINNED["method"],
                PINNED["path"],
                PINNED["timestamp"],
                PINNED["nonce"],
            ),
            "tok_abc123\nPOST\n/v1/messages\n2026-08-09T12:00:00.000Z\nnonce-1",
        )


class ProofTest(unittest.TestCase):
    def test_pinned_cross_language_vector(self) -> None:
        self.assertEqual(
            pop_proof(
                PINNED["secret"],
                PINNED["token_id"],
                PINNED["method"],
                PINNED["path"],
                PINNED["timestamp"],
                PINNED["nonce"],
            ),
            PINNED["proof"],
        )


class HeadersTest(unittest.TestCase):
    def test_headers_shape_and_query_stripping(self) -> None:
        creds = TokenCredentials(token_id=PINNED["token_id"], pop_secret=PINNED["secret"])
        headers = token_auth_headers(
            creds,
            "POST",
            "/v1/messages?ignored=1",
            timestamp=PINNED["timestamp"],
            nonce=PINNED["nonce"],
        )
        self.assertEqual(headers["x-mandare-token"], PINNED["token_id"])
        self.assertEqual(headers["x-mandare-timestamp"], PINNED["timestamp"])
        self.assertEqual(headers["x-mandare-nonce"], PINNED["nonce"])
        self.assertEqual(headers["x-mandare-pop"], PINNED["proof"])

    def test_fresh_nonce_per_call(self) -> None:
        creds = TokenCredentials(token_id="t", pop_secret="s")
        first = token_auth_headers(creds, "POST", "/p")
        second = token_auth_headers(creds, "POST", "/p")
        self.assertNotEqual(first["x-mandare-nonce"], second["x-mandare-nonce"])


class SecretHygieneTest(unittest.TestCase):
    """R2: the PoP secret never reaches logs, tracebacks or f-strings (S-7)."""

    def test_repr_and_str_do_not_reveal_the_secret(self) -> None:
        creds = TokenCredentials(token_id="tok_visible", pop_secret="pop-SECRET-value")
        for rendered in (repr(creds), str(creds), f"{creds}", f"{creds!r}", f"{[creds]}"):
            self.assertNotIn("pop-SECRET-value", rendered)
            self.assertIn("tok_visible", rendered)  # the public id stays debuggable

    def test_the_secret_still_signs(self) -> None:
        creds = TokenCredentials(token_id=PINNED["token_id"], pop_secret=PINNED["secret"])
        self.assertEqual(creds.pop_secret, PINNED["secret"])


if __name__ == "__main__":
    unittest.main()
