import {
  AGENT_REINSTATE,
  AGENT_REVOKE,
  agentSubject,
  doorSubject,
  mandateSubject,
  revocationProjector,
} from '@mandarelabs/ledger';
import { canonicalJson, sha256Hex } from '@mandarelabs/spec';

import { closeDoorContext, openDoorContext, type DoorContext } from './door-context.js';

/**
 * `mandare kill <agent>` — the authoritative, LOCAL, offline kill switch
 * (founder ruling). It writes an `agent.revoke` entry to the ledger and flips
 * the revocation projection in the SAME transaction; the gateway honors it on
 * its very next request without any network round-trip, so a kill cannot be
 * jammed. As belt-and-suspenders it also tells the vault to stop honoring the
 * actor's tokens (and, later, disables the OpenRouter provisioning key).
 *
 * The revocation record is already the W3C bitstring status-list shape S6 will
 * publish unchanged — one revocation vocabulary (see `mandare verify`).
 */

export interface KillOptions {
  agent?: string;
  all?: boolean;
  /** Revoke a MANDATE (S4): the permission slip dies, the agent survives. */
  mandate?: string;
  reason?: string;
}

export async function runKill(
  env: Record<string, string | undefined>,
  options: KillOptions
): Promise<number> {
  const killsMandate = options.mandate !== undefined && options.mandate !== '';
  if (options.all !== true && !killsMandate && (options.agent === undefined || options.agent === '')) {
    process.stderr.write('error: kill requires <agent>, --mandate <id>, or --all\n');
    return 2;
  }
  const ctx = await openDoorContext(env);
  try {
    const subject =
      options.all === true
        ? doorSubject(ctx.doorId)
        : killsMandate
          ? mandateSubject(options.mandate as string)
          : agentSubject(options.agent as string);
    const entry = await appendRevocation(ctx, AGENT_REVOKE, subject, options.reason);
    // Belt-and-suspenders: the vault stops honoring the actor's tokens too. In
    // legacy mode there is no vault (and no scoped tokens), so this is a no-op
    // and the ledger revoke alone is the authority. A mandate kill revokes no
    // tokens: the AGENT keeps its identity; only this permission slip dies.
    const tokensRevoked =
      ctx.vault === null || killsMandate
        ? null
        : options.all === true
          ? ctx.vault.revokeAllTokens()
          : ctx.vault.revokeActorTokens(options.agent as string);

    process.stdout.write(
      `KILLED ${
        options.all === true
          ? `door ${ctx.doorId} (kill --all)`
          : killsMandate
            ? `mandate ${options.mandate as string}`
            : (options.agent as string)
      }\n`
    );
    process.stdout.write(`  subject:      ${subject}\n`);
    process.stdout.write(`  ledger entry: ${entry.entry_hash} (seq ${entry.seq})\n`);
    process.stdout.write(
      `  door key:     ${ctx.ledger.doorKeyId.slice(0, 12)}… (provenance: ${ctx.ledger.doorKeyProvenance})\n`
    );
    process.stdout.write(
      `  vault:        ${
        killsMandate
          ? 'untouched (mandate kill — the agent keeps its identity, only this permission slip dies)'
          : tokensRevoked === null
            ? 'legacy mode (no scoped tokens)'
            : `${tokensRevoked} live token(s) revoked`
      }\n`
    );
    if (options.reason !== undefined) {
      process.stdout.write(`  reason:       ${options.reason} (committed in the entry's request_hash)\n`);
    }
    process.stdout.write(
      '  status:       written to the LOCAL ledger — the gateway fails closed on its next request (offline, un-jammable)\n'
    );
    return 0;
  } finally {
    await closeDoorContext(ctx);
  }
}

export async function runReinstate(
  env: Record<string, string | undefined>,
  options: { agent?: string; reason?: string }
): Promise<number> {
  if (options.agent === undefined || options.agent === '') {
    process.stderr.write('error: reinstate requires <agent>\n');
    return 2;
  }
  const ctx = await openDoorContext(env);
  try {
    const subject = agentSubject(options.agent);
    const entry = await appendRevocation(ctx, AGENT_REINSTATE, subject, options.reason);
    process.stdout.write(`REINSTATED ${options.agent}\n`);
    process.stdout.write(`  subject:      ${subject}\n`);
    process.stdout.write(`  ledger entry: ${entry.entry_hash} (seq ${entry.seq})\n`);
    process.stdout.write(
      '  note:         the vault will honor NEW tokens for this actor; previously-killed tokens stay dead\n'
    );
    return 0;
  } finally {
    await closeDoorContext(ctx);
  }
}

async function appendRevocation(
  ctx: DoorContext,
  type: typeof AGENT_REVOKE | typeof AGENT_REINSTATE,
  subject: string,
  reason: string | undefined
) {
  // The kill context (subject + reason) is committed via request_hash so the
  // reason is tamper-evident even though it is not a schema field.
  const requestHash = sha256Hex(
    canonicalJson({ op: type, subject, reason: reason ?? null })
  );
  const result = await ctx.ledger.appendProjected(
    {
      actor: ctx.killActor,
      mandate_id: 'mandare:kill',
      action: { type, target: subject, request_hash: requestHash },
      cost: { amount: 0, currency: ctx.ledgerCurrency, tokens_in: 0, tokens_out: 0 },
    },
    revocationProjector()
  );
  if (result.kind !== 'appended') {
    throw new Error('kill append was refused — this should never happen for a revocation entry');
  }
  return result.entry;
}
