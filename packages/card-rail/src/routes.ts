import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import {
  APPROVAL_DENIED,
  APPROVAL_EXPIRED,
  APPROVAL_GRANTED,
  APPROVAL_REQUESTED,
  CARD_AUTH_DENIED,
  CARD_AUTH_INTENT,
  CARD_AUTH_RESULT,
  SUBJECT_REGISTER,
  agentSubject,
  cardAuthKey,
  cardSubject,
  doorSubject,
  mandateSubject,
  readSpendSnapshot,
  revocationProjector,
  spendProjector,
  type SpendGuardView,
} from '@mandarelabs/ledger';
import {
  checkBudgets,
  selectCardSpendScope,
  spendLimitsFromScope,
} from '@mandarelabs/policy-engine';
import { canonicalJson, sha256Hex, type LedgerEntryV1, type SpendScope } from '@mandarelabs/spec';

import { isSupportedCardCurrency, microsToMinorUnitsFloor, minorUnitsToMicros } from './amounts.js';
import {
  authorizationRequestHash,
  decisionResponseHash,
  isPartialableRefusal,
  maxApprovableMicros,
  parseAuthorizationEvent,
  type AuthorizationRequest,
} from './authorization.js';
import { CARD_CREATE_INTENT, CARD_CREATE_RESULT, CardRegistry } from './registry.js';
import { verifyStripeSignature } from './webhook-signature.js';
import type { CardRailDeps } from './types.js';

/** Failed creations still settle the intent (R3) — under a non-card target. */
export const CARD_CREATE_FAILED = 'card.create.failed';

const REVOKED_DENIED_THROTTLE_MS = 1_000;

/** Live door state for the mounting door's /healthz (review LOW-5). */
export interface CardRailStatus {
  /** True after an unrecordable decision halted the card door (declines everything). */
  isHalted(): boolean;
  registeredCards(): number;
}

/**
 * Mount the card rail onto a door's Fastify app. The webhook route lives in
 * an encapsulated scope with a RAW-BODY parser: the Stripe signature is
 * computed over exact bytes, so nothing may parse them first.
 *
 * Decision path budget (Q11): Stripe expects the authorization answer within
 * 2 seconds. Everything on the path is local — signature HMAC, projection
 * reads, two fsync'd appends — benchmarked orders of magnitude under it.
 * The dashboard default for webhook timeouts MUST be set to DECLINE
 * (docs/CARD-RAIL.md) so a door outage fails closed at Stripe too.
 */
export async function registerCardRail(
  app: FastifyInstance,
  deps: CardRailDeps
): Promise<CardRailStatus> {
  const { config, ledger, policy, mandate, approvals, waivers, notifier, witnessGate } = deps;
  const clock = deps.clock ?? ((): Date => new Date());
  const registry =
    deps.registry ??
    CardRegistry.fromEntries(await ledger.runProjection((tx) => tx.readAllEntries()));
  let halted = false;
  let lastRevokedDeniedAt = 0;
  // Authorization ids with a step-up approval currently in flight: a
  // replayed webhook for one of these writes NOTHING and pushes nothing —
  // one authorization, one pending question, one possible waiver (review
  // S5 LOW-1, the undecided-replay flavor). Entries clear when the human
  // decides or the approval times out (both paths resolve the outcome).
  const pendingStepUps = new Set<string>();

  const scopeSelection = selectCardSpendScope(mandate);
  const cardScope: SpendScope | null =
    scopeSelection === 'none' || scopeSelection === 'ambiguous' ? null : scopeSelection;

  await app.register(async (webhookScope) => {
    webhookScope.addContentTypeParser(
      'application/json',
      { parseAs: 'buffer' },
      (_request, body, done) => done(null, body)
    );
    webhookScope.post('/stripe/webhook', async (request, reply) => handleWebhook(request, reply));
  });

  app.post('/cards', async (request, reply) => handleCreateCard(request, reply));

  // Inner handlers are function declarations (hoisted) — returning here is
  // safe and keeps the wiring at the top of the plugin.
  return {
    isHalted: () => halted,
    registeredCards: () => registry.size(),
  };

  // --- the authorization decision path ---------------------------------------

  async function handleWebhook(request: FastifyRequest, reply: FastifyReply): Promise<unknown> {
    // 1. Signature FIRST (mandatory, fail-closed): an unsigned or forged
    //    webhook gets a 4xx and touches NOTHING — not the ledger, not the
    //    counters, not even a log entry an attacker could flood.
    const rawBody = Buffer.isBuffer(request.body) ? request.body : null;
    if (rawBody === null) {
      return reply.code(400).send({ error: 'missing body' });
    }
    const verdict = verifyStripeSignature({
      payload: rawBody,
      header: request.headers['stripe-signature'] as string | undefined,
      secret: config.webhookSecret,
      toleranceSeconds: config.webhookToleranceSeconds,
      nowMs: clock().getTime(),
    });
    if (!verdict.ok) {
      return reply.code(verdict.failure === 'SIGNATURE_MISMATCH' ? 401 : 400).send({
        error: 'webhook signature rejected',
        code: verdict.failure,
      });
    }

    let event: unknown;
    try {
      event = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return reply.code(400).send({ error: 'body is not valid JSON' });
    }
    const eventType = (event as { type?: unknown }).type;
    if (eventType !== 'issuing_authorization.request') {
      // Other event types are acknowledged and ignored in v0 (the
      // settlement true-up from issuing_transaction.created is scheduled
      // work — see docs/CARD-RAIL.md).
      return reply.code(200).send({ received: true });
    }
    const auth = parseAuthorizationEvent(event);
    if (auth === null) {
      // Signed but malformed — a schema surprise is a decline, not a guess.
      return reply.code(200).send({ approved: false });
    }
    return decideAuthorization(auth, reply);
  }

  async function decideAuthorization(
    auth: AuthorizationRequest,
    reply: FastifyReply
  ): Promise<unknown> {
    const respond = (approved: boolean, partialMicros?: number): unknown => {
      if (auth.apiVersion !== null) {
        void reply.header('stripe-version', auth.apiVersion);
      }
      return reply.code(200).send({
        approved,
        ...(partialMicros === undefined ? {} : { amount: microsToMinorUnitsFloor(partialMicros) }),
      });
    };
    const requestHash = authorizationRequestHash(auth);
    const decline = async (args: {
      code: string;
      reason: string;
      actor: string;
      mandateId: string;
      amountMicros: number;
      skipLedger?: boolean;
    }): Promise<unknown> => {
      if (args.skipLedger !== true) {
        await recordDenied({ ...args, requestHash, target: auth.authorizationId });
      }
      return respond(false);
    };

    if (halted) {
      return decline({
        code: 'DOOR_HALTED',
        reason: 'card door halted after an unrecorded decision — declining everything',
        actor: 'unknown',
        mandateId: mandate.id,
        amountMicros: auth.requestedMicros,
        skipLedger: true,
      });
    }

    // 2. Card → (actor, mandate) binding. Unknown card = a card this door
    //    never created under its mandate — decline, on the record.
    const binding = registry.get(auth.cardId);
    if (binding === null) {
      return decline({
        code: 'CARD_UNKNOWN',
        reason: `card ${auth.cardId} is not bound to any mandate at this door (fail-closed)`,
        actor: 'unknown',
        mandateId: 'mnd_unknown',
        amountMicros: auth.requestedMicros,
      });
    }
    if (binding.mandateId !== mandate.id) {
      return decline({
        code: 'MANDATE_MISMATCH',
        reason: `card ${auth.cardId} was issued under mandate ${binding.mandateId}, not the one this door enforces`,
        actor: binding.actor,
        mandateId: binding.mandateId,
        amountMicros: auth.requestedMicros,
      });
    }
    const actor = binding.actor;

    // 2b. Replay, checked EARLY (review LOW-1): once an authorization id has
    //     ever been decided, any replay — whatever the budget looks like now
    //     — is refused without a single ledger write. (The in-transaction
    //     marker check below remains the authoritative race-proof guard.)
    let alreadyDecided: boolean;
    try {
      alreadyDecided = await ledger.runProjection(
        async (tx) => (await tx.getCounter(cardAuthKey(auth.authorizationId))) !== null
      );
    } catch {
      alreadyDecided = false; // the reserve step fails closed regardless
    }
    if (alreadyDecided) {
      return decline({
        code: 'AUTH_REPLAYED',
        reason: `card authorization ${auth.authorizationId} was already decided — refusing a replay`,
        actor,
        mandateId: mandate.id,
        amountMicros: auth.requestedMicros,
        skipLedger: true,
      });
    }

    // 3. Kill switch — door, agent, mandate, and the CARD itself, read from
    //    the LOCAL revocation projection (S3 authority; `mandare kill` in
    //    another process bites here on the very next authorization).
    const revocation = await readRevocationRefusal(actor, auth.cardId);
    if (revocation === 'unavailable') {
      return decline({
        code: 'REVOCATION_UNAVAILABLE',
        reason: 'revocation status unavailable — declining (fail-closed)',
        actor,
        mandateId: mandate.id,
        amountMicros: auth.requestedMicros,
        skipLedger: true,
      });
    }
    if (revocation !== null) {
      const nowMs = clock().getTime();
      const throttled = nowMs - lastRevokedDeniedAt < REVOKED_DENIED_THROTTLE_MS;
      if (!throttled) {
        lastRevokedDeniedAt = nowMs;
      }
      return decline({
        code: revocation.code,
        reason: revocation.reason,
        actor,
        mandateId: mandate.id,
        amountMicros: auth.requestedMicros,
        skipLedger: throttled,
      });
    }

    // 4. Currency sanity before any arithmetic (R1: no invented conversion).
    if (!isSupportedCardCurrency(auth.currency)) {
      return decline({
        code: 'CURRENCY_UNSUPPORTED',
        reason: `currency ${auth.currency} is not a supported two-decimal currency — cannot meter it (fail-closed)`,
        actor,
        mandateId: mandate.id,
        amountMicros: 0,
      });
    }
    if (auth.currency !== config.ledgerCurrency) {
      return decline({
        code: 'CURRENCY_MISMATCH',
        reason: `authorization is in ${auth.currency} but the ledger runs ${config.ledgerCurrency} — refusing to convert implicitly`,
        actor,
        mandateId: mandate.id,
        amountMicros: auth.requestedMicros,
      });
    }
    if (cardScope === null) {
      return decline({
        code: 'SCOPE_MISMATCH',
        reason:
          scopeSelection === 'ambiguous'
            ? 'multiple spend scopes cover the card rail — refusing ambiguous budgets (fail-closed)'
            : "mandate has no spend scope covering the 'card' rail",
        actor,
        mandateId: mandate.id,
        amountMicros: auth.requestedMicros,
      });
    }

    // 5. Policy (SPEC §5 order) at the requested amount.
    let decision = await evaluatePolicy(actor, auth, auth.requestedMicros);
    let approvedMicros = auth.requestedMicros;
    let isPartial = false;

    if (decision.decision !== 'allow' && decision.code === 'APPROVAL_REQUIRED') {
      // Step-up: a prior human approval for this card+merchant (minted from
      // a recorded approval.granted entry) waives the threshold for ONE
      // retry; otherwise decline now and push the question to the human.
      // An UNIDENTIFIABLE merchant (no network_id, no name) gets no waiver
      // in either direction — the human cannot approve what cannot be named
      // (review LOW-2: never pool merchants under a shared sentinel key).
      const waiver =
        auth.merchantKey === null
          ? null
          : waivers.consume({
              cardId: auth.cardId,
              merchantKey: auth.merchantKey,
              amountMicros: auth.requestedMicros,
            });
      if (waiver !== null) {
        decision = await evaluatePolicy(actor, auth, auth.requestedMicros, waiver.grantedEntryHash);
      } else {
        return declineWithStepUp(auth, actor, requestHash, decision.reasons, reply, respond);
      }
    }

    if (
      decision.decision !== 'allow' &&
      auth.isAmountControllable &&
      isPartialableRefusal(decision.code)
    ) {
      // Partial approval (Q11): the merchant asked for more than fits, but
      // marked the amount controllable. Approve what the caps still allow —
      // floored to whole minor units, and only if the FULL policy order
      // allows the reduced amount (this is a real allow, not a shortcut).
      const snapshot = await readSpendSnapshot(ledger, {
        mandateId: mandate.id,
        actor,
        nowIso: clock().toISOString(),
      });
      const partialMicros = minorUnitsToMicros(
        microsToMinorUnitsFloor(maxApprovableMicros(cardScope, snapshot))
      );
      if (partialMicros > 0 && partialMicros < auth.requestedMicros) {
        const partialDecision = await evaluatePolicy(actor, auth, partialMicros);
        if (partialDecision.decision === 'allow') {
          decision = partialDecision;
          approvedMicros = partialMicros;
          isPartial = true;
        }
      }
    }

    if (decision.decision !== 'allow') {
      return decline({
        code: decision.code ?? 'POLICY_DENIED',
        reason: decision.reasons.join('; '),
        actor,
        mandateId: mandate.id,
        amountMicros: auth.requestedMicros,
      });
    }

    // 6. RESERVE (log-before-act, R3): the intent entry carries the approved
    //    amount, budget-guarded INSIDE the append transaction — the same
    //    lock LLM spend reserves under, so a race between the two rails (or
    //    two authorizations) can never pierce the shared cap.
    const guard = (view: SpendGuardView) =>
      checkBudgets({
        limits: spendLimitsFromScope(cardScope),
        velocity: { maxIntentsPerMinute: config.maxIntentsPerMinute },
        counters: {
          minuteIntents: view.minuteIntents,
          day: { reservedMicros: view.day.reservedMicros, settledMicros: view.day.settledMicros },
          task: { reservedMicros: view.total.reservedMicros, settledMicros: view.total.settledMicros },
          total: { reservedMicros: view.total.reservedMicros, settledMicros: view.total.settledMicros },
        },
        estimateMicros: view.estimateMicros,
        currency: view.currency,
      });
    let reservation;
    try {
      reservation = await ledger.appendProjected(
        {
          actor,
          mandate_id: mandate.id,
          action: { type: CARD_AUTH_INTENT, target: auth.authorizationId, request_hash: requestHash },
          cost: { amount: approvedMicros, currency: config.ledgerCurrency, tokens_in: 0, tokens_out: 0 },
        },
        spendProjector(guard)
      );
    } catch {
      return decline({
        code: 'LEDGER_UNAVAILABLE',
        reason: 'ledger unavailable — declining (fail-closed)',
        actor,
        mandateId: mandate.id,
        amountMicros: approvedMicros,
        skipLedger: true,
      });
    }
    if (reservation.kind === 'refused') {
      // AUTH_REPLAYED: this authorization was already decided once — a
      // replayed delivery gets a decline and NO second ledger entry (a
      // replay must not be able to make the door write).
      const replayed = reservation.refusal.code === 'AUTH_REPLAYED';
      return decline({
        code: reservation.refusal.code,
        reason: reservation.refusal.reason,
        actor,
        mandateId: mandate.id,
        amountMicros: approvedMicros,
        skipLedger: replayed,
      });
    }

    // 6b. Witness-ack gating (S6, lock 5): a high-value authorization's
    //     intent must be witnessed off-machine BEFORE Stripe hears
    //     "approved" — the ack pins the head containing the intent entry.
    //     No verified ack ⇒ settle the reservation to ZERO and decline
    //     (fail-closed): a dead witness closes the card door for high-value
    //     purchases, it never opens it. The consumed step-up waiver is spent
    //     — after the witness recovers, the human simply approves again.
    if (witnessGate !== undefined && witnessGate.isGated(approvedMicros, mandate)) {
      const verdict = await witnessGate.requireAck();
      if (!verdict.ok) {
        const released = await settleAuthorization(reservation.entry, auth, 0);
        if (released === null) {
          halted = true;
        }
        return respond(false);
      }
      // The ack wait is a window in which a `mandare kill` can commit; a
      // high-value authorization must NOT be approved after it. Re-check
      // revocation after the ack (HIGH-2 parity with the gateway path) and, if
      // the actor/card was killed mid-wait, release the reservation and decline
      // (fail-closed — 'unavailable' declines too).
      const ackRevocation = await readRevocationRefusal(actor, auth.cardId);
      if (ackRevocation !== null) {
        const released = await settleAuthorization(reservation.entry, auth, 0);
        if (released === null) {
          halted = true;
        }
        return respond(false);
      }
    }

    // 7. SETTLE: the approval decision is the act; its record must exist
    //    before Stripe hears "approved". A result that cannot be persisted
    //    halts the card door — decline now and everything after (R3).
    const settled = await settleAuthorization(reservation.entry, auth, approvedMicros);
    if (settled === null) {
      halted = true;
      return respond(false);
    }
    return respond(true, isPartial ? approvedMicros : undefined);
  }

  // --- helpers ----------------------------------------------------------------

  async function evaluatePolicy(
    actor: string,
    auth: AuthorizationRequest,
    estimateMicros: number,
    approvedEntryHash?: string
  ) {
    const snapshot = await readSpendSnapshot(ledger, {
      mandateId: mandate.id,
      actor,
      nowIso: clock().toISOString(),
    });
    const counterparty = auth.merchantKey ?? auth.merchantName;
    return policy.evaluate({
      principal: actor,
      action: 'card.purchase',
      resource: counterparty,
      context: {
        estimateMicros,
        currency: auth.currency,
        counterparty,
        counters: {
          minuteIntents: snapshot.minuteIntents,
          day: { reservedMicros: snapshot.day.reservedMicros, settledMicros: snapshot.day.settledMicros },
          task: {
            reservedMicros: snapshot.total.reservedMicros,
            settledMicros: snapshot.total.settledMicros,
          },
          total: {
            reservedMicros: snapshot.total.reservedMicros,
            settledMicros: snapshot.total.settledMicros,
          },
        },
        ...(approvedEntryHash === undefined ? {} : { approvedEntryHash }),
      },
    });
  }

  /**
   * The 2-second budget cannot hold a human decision, so over-threshold =
   * DECLINE NOW + the S4 approval push. A granted approval is recorded on
   * the ledger and minted into a single-use waiver; the human then simply
   * retries the purchase. Every failure on the async path means: no waiver.
   */
  function declineWithStepUp(
    auth: AuthorizationRequest,
    actor: string,
    requestHash: string,
    reasons: readonly string[],
    _reply: FastifyReply,
    respond: (approved: boolean) => unknown
  ): unknown {
    if (pendingStepUps.has(auth.authorizationId)) {
      // A replay (or double delivery) while the human is already being
      // asked about THIS authorization: decline silently — no second
      // denied entry, no second push, no second waiver path.
      return respond(false);
    }
    if (auth.merchantKey === null) {
      void recordDenied({
        code: 'APPROVAL_REQUIRED',
        reason: `${reasons.join('; ')}; merchant is unidentifiable (no network id or name) — an approval could not be safely waived, declined (fail-closed)`,
        actor,
        mandateId: mandate.id,
        amountMicros: auth.requestedMicros,
        requestHash,
        target: auth.authorizationId,
      });
      return respond(false);
    }
    if (notifier === undefined) {
      void recordDenied({
        code: 'APPROVAL_REQUIRED',
        reason: `${reasons.join('; ')}; no approval push channel configured — declined (fail-closed)`,
        actor,
        mandateId: mandate.id,
        amountMicros: auth.requestedMicros,
        requestHash,
        target: auth.authorizationId,
      });
      return respond(false);
    }
    if (approvals.pendingCount() >= config.maxPendingApprovals) {
      void recordDenied({
        code: 'APPROVAL_BACKLOG',
        reason: `too many approvals already awaiting a human decision (≥${config.maxPendingApprovals}) — declined without a push (fail-closed)`,
        actor,
        mandateId: mandate.id,
        amountMicros: auth.requestedMicros,
        requestHash,
        target: auth.authorizationId,
      });
      return respond(false);
    }
    void recordDenied({
      code: 'APPROVAL_REQUIRED',
      reason: `${reasons.join('; ')}; declined at the network — approval push sent, an approved retry will pass`,
      actor,
      mandateId: mandate.id,
      amountMicros: auth.requestedMicros,
      requestHash,
      target: auth.authorizationId,
    });
    // Fire-and-forget: the webhook answer must not wait on the push channel.
    pendingStepUps.add(auth.authorizationId);
    void runStepUpApproval(auth, auth.merchantKey, actor, requestHash)
      .catch(() => {
        // Fail closed: any error on this path means no waiver is minted.
      })
      .finally(() => {
        pendingStepUps.delete(auth.authorizationId);
      });
    return respond(false);
  }

  async function runStepUpApproval(
    auth: AuthorizationRequest,
    merchantKey: string,
    actor: string,
    requestHash: string
  ): Promise<void> {
    // Log-before-push (R3): the approval request is on the record before the
    // human can see it.
    const requested = await ledger.appendProjected(
      {
        actor,
        mandate_id: mandate.id,
        action: { type: APPROVAL_REQUESTED, target: merchantKey, request_hash: requestHash },
        cost: { amount: auth.requestedMicros, currency: config.ledgerCurrency, tokens_in: 0, tokens_out: 0 },
      },
      spendProjector()
    );
    if (requested.kind !== 'appended') {
      return;
    }
    const thresholds = mandate.approvals.rules
      .filter((rule) => auth.requestedMicros > rule.above)
      .map((rule) => rule.above);
    const created = approvals.create({
      requestHash,
      estimateMicros: auth.requestedMicros,
      currency: config.ledgerCurrency,
      model: 'card.purchase',
      target: auth.merchantName,
      actor,
      mandateId: mandate.id,
      thresholdMicros: thresholds.length === 0 ? 0 : Math.min(...thresholds),
    });
    const amount = (auth.requestedMicros / 1_000_000).toFixed(2);
    await (notifier as NonNullable<typeof notifier>).send({
      approvalId: created.id,
      title: `Mandare: card purchase ${amount} ${config.ledgerCurrency}?`,
      message:
        `Agent ${actor} tried to pay ${amount} ${config.ledgerCurrency} to ` +
        `${auth.merchantName} — above your approval threshold, so the card DECLINED at the ` +
        `network. Approve to allow ONE retry of this purchase (mandate ${mandate.id}). ` +
        `No decision by ${created.expiresAtIso} = stays declined.`,
      approveUrl: `${config.approvalBaseUrl}/approvals/${created.id}`,
      denyUrl: `${config.approvalBaseUrl}/approvals/${created.id}`,
      approveBody: JSON.stringify({ token: created.approveToken }),
      denyBody: JSON.stringify({ token: created.denyToken }),
      expiresAt: created.expiresAtIso,
    });
    const outcome = await created.outcome;
    const decisionType =
      outcome === 'approved' ? APPROVAL_GRANTED : outcome === 'denied' ? APPROVAL_DENIED : APPROVAL_EXPIRED;
    const decisionHash = sha256Hex(
      canonicalJson({ approval_id: created.id, decision: outcome, request_hash: requestHash })
    );
    const decisionEntry = await ledger.appendProjected(
      {
        // Human decisions are attributed to the accountable human (S4 rule).
        actor: mandate.principal,
        mandate_id: mandate.id,
        action: { type: decisionType, target: merchantKey, request_hash: decisionHash },
        cost: { amount: 0, currency: config.ledgerCurrency, tokens_in: 0, tokens_out: 0 },
        outcome_ref: requested.entry.entry_hash,
      },
      spendProjector()
    );
    if (outcome === 'approved' && decisionEntry.kind === 'appended') {
      // The waiver exists ONLY because a recorded approval.granted entry
      // exists — no entry, no waiver (R3).
      waivers.grant({
        cardId: auth.cardId,
        merchantKey,
        maxAmountMicros: auth.requestedMicros,
        grantedEntryHash: decisionEntry.entry.entry_hash,
      });
    }
  }

  async function settleAuthorization(
    intent: LedgerEntryV1,
    auth: AuthorizationRequest,
    approvedMicros: number
  ): Promise<LedgerEntryV1 | null> {
    try {
      const appended = await ledger.appendProjected(
        {
          actor: intent.actor,
          mandate_id: intent.mandate_id,
          action: {
            type: CARD_AUTH_RESULT,
            target: auth.authorizationId,
            request_hash: intent.action.request_hash,
            response_hash: decisionResponseHash(auth, approvedMicros),
          },
          cost: { amount: approvedMicros, currency: config.ledgerCurrency, tokens_in: 0, tokens_out: 0 },
          outcome_ref: intent.entry_hash,
        },
        spendProjector()
      );
      return appended.kind === 'appended' ? appended.entry : null;
    } catch {
      return null;
    }
  }

  async function recordDenied(args: {
    code: string;
    reason: string;
    actor: string;
    mandateId: string;
    amountMicros: number;
    requestHash: string;
    target: string;
  }): Promise<void> {
    try {
      await ledger.appendProjected(
        {
          actor: args.actor,
          mandate_id: args.mandateId,
          action: { type: CARD_AUTH_DENIED, target: args.target, request_hash: args.requestHash },
          cost: { amount: args.amountMicros, currency: config.ledgerCurrency, tokens_in: 0, tokens_out: 0 },
        },
        spendProjector()
      );
    } catch {
      // The decline stands even unrecorded; a down ledger never opens spend.
    }
  }

  async function readRevocationRefusal(
    actor: string,
    cardId: string
  ): Promise<{ code: string; reason: string } | 'unavailable' | null> {
    let records;
    try {
      records = await ledger.runProjection(async (tx) => ({
        door: await tx.getRevocation(doorSubject(config.doorId)),
        agent: await tx.getRevocation(agentSubject(actor)),
        mandate: await tx.getRevocation(mandateSubject(mandate.id)),
        card: await tx.getRevocation(cardSubject(cardId)),
      }));
    } catch {
      return 'unavailable';
    }
    if (records.door?.revoked === true) {
      return {
        code: 'DOOR_REVOKED',
        reason: `door '${config.doorId}' has been killed (kill --all) — every credential is revoked (fail-closed)`,
      };
    }
    if (records.agent?.revoked === true) {
      return {
        code: 'AGENT_REVOKED',
        reason: `agent '${actor}' has been killed — its cards decline at the network (fail-closed)`,
      };
    }
    if (records.mandate?.revoked === true) {
      return {
        code: 'MANDATE_REVOKED',
        reason: `mandate '${mandate.id}' has been revoked — the permission slip is dead paper (fail-closed)`,
      };
    }
    if (records.card?.revoked === true) {
      return {
        code: 'CARD_REVOKED',
        reason: `card '${cardId}' has been revoked — dead plastic (fail-closed)`,
      };
    }
    return null;
  }

  // --- card creation (a mandate-checked, ledger-logged door op) ---------------

  async function handleCreateCard(request: FastifyRequest, reply: FastifyReply): Promise<unknown> {
    if (halted) {
      return reply.code(503).send({ error: 'card door halted — investigate before creating cards' });
    }
    const authn = await deps.authenticateCreate(request);
    if (!authn.ok) {
      return reply.code(authn.status).send(authn.body);
    }
    const actor = authn.actor;
    if (deps.stripe === null || config.cardholderId === null) {
      return reply.code(503).send({
        error: 'card creation unavailable: Stripe credentials or cardholder not configured (fail-closed)',
      });
    }
    const revocation = await readRevocationRefusal(actor, 'card:none');
    if (revocation === 'unavailable') {
      return reply.code(503).send({ error: 'revocation status unavailable — refusing (fail-closed)' });
    }
    if (revocation !== null) {
      return reply.code(403).send({ error: 'denied by policy', code: revocation.code, reasons: [revocation.reason] });
    }

    // Mandate checks for the CREATE op itself: window valid, an action scope
    // granting card.create, and exactly one card spend scope in the ledger
    // currency (its per-tx cap becomes the Stripe-side belt).
    const from = Date.parse(mandate.valid_from);
    const until = Date.parse(mandate.valid_until);
    const now = clock().getTime();
    if (Number.isNaN(from) || Number.isNaN(until) || now < from || now > until) {
      return reply.code(403).send({
        error: 'denied by policy',
        code: 'MANDATE_OUT_OF_WINDOW',
        reasons: [`mandate ${mandate.id} is not currently valid — card creation refused (fail-closed)`],
      });
    }
    const actionGranted = mandate.scopes.some(
      (scope) => scope.type === 'action' && scope.classes.includes('card.create')
    );
    if (!actionGranted) {
      return reply.code(403).send({
        error: 'denied by policy',
        code: 'SCOPE_MISMATCH',
        reasons: ["no action scope grants 'card.create' — card creation refused"],
      });
    }
    if (actor !== mandate.agent) {
      return reply.code(403).send({
        error: 'denied by policy',
        code: 'IDENTITY_MISMATCH',
        reasons: [`actor ${actor} is not the mandated agent ${mandate.agent}`],
      });
    }
    if (cardScope === null) {
      return reply.code(403).send({
        error: 'denied by policy',
        code: 'SCOPE_MISMATCH',
        reasons: ["mandate has no unambiguous spend scope covering the 'card' rail"],
      });
    }
    if (cardScope.currency !== config.ledgerCurrency) {
      return reply.code(503).send({
        error: `mandate budgets ${cardScope.currency} but the ledger runs ${config.ledgerCurrency} — refusing (fail-closed)`,
      });
    }

    // RESERVE nothing, but LOG before acting (R3): creation is an intent/
    // result pair like any other door op.
    const createHash = sha256Hex(
      canonicalJson({ op: 'card.create', actor, mandate_id: mandate.id, cardholder: config.cardholderId })
    );
    let intent: LedgerEntryV1;
    try {
      const appended = await ledger.appendProjected(
        {
          actor,
          mandate_id: mandate.id,
          action: { type: CARD_CREATE_INTENT, target: 'stripe:issuing.card', request_hash: createHash },
          cost: { amount: 0, currency: config.ledgerCurrency, tokens_in: 0, tokens_out: 0 },
        },
        spendProjector()
      );
      if (appended.kind !== 'appended') {
        throw new Error('card.create.intent refused');
      }
      intent = appended.entry;
    } catch {
      return reply.code(503).send({ error: 'ledger unavailable — refusing to act (fail-closed)' });
    }

    let card;
    try {
      card = await deps.stripe.createCard({
        cardholderId: config.cardholderId,
        currency: config.ledgerCurrency,
        perAuthorizationLimitMinorUnits: Math.max(1, microsToMinorUnitsFloor(cardScope.per_tx_max)),
        metadata: { mandare_mandate: mandate.id, mandare_actor: actor },
      });
    } catch (error) {
      // The act failed — settle the intent honestly (R3: no unpaired intent)
      // under a failure type the registry ignores.
      const errorName = error instanceof Error ? error.name : 'UnknownError';
      await appendCreateOutcome(actor, CARD_CREATE_FAILED, 'stripe:error', createHash, intent, errorName);
      return reply.code(502).send({ error: 'Stripe card creation failed — nothing was issued' });
    }

    const result = await appendCreateOutcome(actor, CARD_CREATE_RESULT, card.id, createHash, intent, null);
    if (result === null) {
      // Created at Stripe but unrecordable here: halt the door (the one
      // state we refuse to continue from) and try to undo the creation.
      halted = true;
      try {
        await deps.stripe.cancelCard(card.id);
      } catch {
        // The card exists unrecorded — the halt forces the operator to look.
      }
      return reply.code(502).send({
        error: 'card created but the result entry could not be persisted — card door halted, card cancel attempted',
      });
    }
    registry.add({ cardId: card.id, actor, mandateId: mandate.id, createdEntryHash: result.entry_hash });

    // Give the card its revocation slot at birth (S4 pattern) so `mandare
    // kill` can flip it and S6 can publish it.
    try {
      await ledger.appendProjected(
        {
          actor,
          mandate_id: mandate.id,
          action: {
            type: SUBJECT_REGISTER,
            target: cardSubject(card.id),
            request_hash: sha256Hex(canonicalJson({ op: SUBJECT_REGISTER, subject: cardSubject(card.id) })),
          },
          cost: { amount: 0, currency: config.ledgerCurrency, tokens_in: 0, tokens_out: 0 },
        },
        revocationProjector()
      );
    } catch {
      // Registration is a status-list slot, not an enforcement gate — the
      // kill path allocates a slot on first revoke if this failed.
    }

    return reply.code(201).send({
      card_id: card.id,
      last4: card.last4,
      status: card.status,
      currency: config.ledgerCurrency,
      per_authorization_limit_minor_units: Math.max(1, microsToMinorUnitsFloor(cardScope.per_tx_max)),
      intent_entry: intent.entry_hash,
      result_entry: result.entry_hash,
    });
  }

  async function appendCreateOutcome(
    actor: string,
    type: string,
    target: string,
    requestHash: string,
    intent: LedgerEntryV1,
    errorName: string | null
  ): Promise<LedgerEntryV1 | null> {
    try {
      const appended = await ledger.appendProjected(
        {
          actor,
          mandate_id: mandate.id,
          action: {
            type,
            target,
            request_hash: requestHash,
            response_hash: sha256Hex(
              canonicalJson({ op: type, target, error: errorName })
            ),
          },
          cost: { amount: 0, currency: config.ledgerCurrency, tokens_in: 0, tokens_out: 0 },
          outcome_ref: intent.entry_hash,
        },
        spendProjector()
      );
      return appended.kind === 'appended' ? appended.entry : null;
    } catch {
      return null;
    }
  }
}
