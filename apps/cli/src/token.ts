import { Vault, loadVaultConfigFromEnv, MAX_TOKEN_TTL_SECONDS } from '@mandarelabs/vault';

/**
 * `mandare token issue` — mint a short-lived proof-of-possession scoped token
 * for an agent to present to the gateway. The pop secret is printed ONCE; the
 * agent stores it and signs each request with it (a leaked token id without
 * this secret is dead paper). SPEC caps the TTL at 30 minutes.
 */

export interface TokenIssueOptions {
  actor?: string;
  mandate?: string;
  ttlSeconds?: number;
  json?: boolean;
}

export function runTokenIssue(
  env: Record<string, string | undefined>,
  options: TokenIssueOptions
): number {
  if (options.actor === undefined || options.mandate === undefined) {
    process.stderr.write('error: token issue requires --actor <did> and --mandate <id>\n');
    return 2;
  }
  if (
    options.ttlSeconds !== undefined &&
    (!Number.isInteger(options.ttlSeconds) || options.ttlSeconds <= 0 || options.ttlSeconds > MAX_TOKEN_TTL_SECONDS)
  ) {
    process.stderr.write(`error: --ttl must be 1..${MAX_TOKEN_TTL_SECONDS} seconds (SPEC caps at 30 min)\n`);
    return 2;
  }
  const vault = Vault.open(loadVaultConfigFromEnv(env));
  try {
    const grant = vault.issueToken({
      actor: options.actor,
      mandateId: options.mandate,
      ...(options.ttlSeconds === undefined ? {} : { ttlSeconds: options.ttlSeconds }),
    });
    if (options.json === true) {
      // The ONLY time the pop secret leaves the vault — the agent captures it here.
      process.stdout.write(
        `${JSON.stringify(
          {
            token_id: grant.tokenId,
            pop_secret: grant.popSecret,
            actor: grant.actor,
            mandate_id: grant.mandateId,
            issued_at: grant.issuedAt,
            expires_at: grant.expiresAt,
          },
          null,
          2
        )}\n`
      );
    } else {
      process.stdout.write(`scoped token issued for ${grant.actor}\n`);
      process.stdout.write(`  token_id:   ${grant.tokenId}\n`);
      process.stdout.write(`  pop_secret: ${grant.popSecret}  (shown ONCE — store it now)\n`);
      process.stdout.write(`  mandate:    ${grant.mandateId}\n`);
      process.stdout.write(`  expires:    ${grant.expiresAt}\n`);
      process.stdout.write(
        '  present:    x-mandare-token/timestamp/nonce/pop headers, PoP = HMAC(pop_secret, tokenId|METHOD|path|timestamp|nonce)\n'
      );
    }
    return 0;
  } finally {
    vault.close();
  }
}
