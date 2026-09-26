import { readFile, writeFile } from 'node:fs/promises';

import { readLedgerRows, replayRevocation } from '@mandarelabs/ledger';
import { AGENT_STATUS_LIST_ID, buildStatusListPayload } from '@mandarelabs/vault';
import { hexToBytes, isLedgerEntry, sha256HexAsync, type LedgerEntryV1 } from '@mandarelabs/spec';
import {
  computeTreeHead,
  consistencyProof,
  inclusionProof,
  parseStoredEntries,
  verifyChain,
  verifyConsistency,
} from '@mandarelabs/verifier';
import {
  buildIntegrityCertificate,
  fetchVerifiedWitnessedHead,
  parseEpochInclusion,
  parseIntegrityCertificate,
  verifyAggregateInclusion,
  verifyEpochSummary,
  verifyIntegrityCertificate,
  type EpochInclusion,
  type IntegrityCertificate,
} from '@mandarelabs/witness-protocol';

import { openDoorContext, closeDoorContext } from './door-context.js';

/**
 * `mandare certify` (SPEC §9.4): produce the integrity certificate — the
 * checkable statement an insurer/auditor consumes: chain valid · sequence
 * complete · heads match independently witnessed history · root publicly
 * anchored — over owner-SELECTED entries with inclusion proofs. Everything
 * else stays private: undisclosed entries appear only as salted hashes
 * inside proofs.
 *
 * `mandare certify verify` is the OTHER side: a third party checks the
 * certificate with NO ledger access, no Mandare service, and no trust in
 * the file beyond what each check states.
 */

export interface CertifyOptions {
  witnessUrl: string;
  witnessPublicKeyHex: string;
  /** 1-based seqs to disclose (with inclusion proofs). May be empty. */
  discloseSeqs: number[];
  outPath?: string;
  json?: boolean;
}

export async function runCertify(
  env: Record<string, string | undefined>,
  dbPath: string,
  options: CertifyOptions
): Promise<number> {
  const { meta, rows } = readLedgerRows(dbPath);
  const stored = parseStoredEntries(rows);
  if (!stored.ok) {
    process.stderr.write(
      `certify: REFUSED — stored entry at seq ${stored.failure.seq ?? '?'} is unsound: ` +
        `[${stored.failure.code}] ${stored.failure.reason}\n`
    );
    return 1;
  }
  const entries = stored.entries;

  // 0. The certified source must BE the key the chain verifies under (W-1 /
  //    S8/C1): a repointed door_key_id would fetch — and embed — another
  //    source's witnessed history. The door context below binds the signing
  //    key to door_key_id, so all three are one identity.
  if ((await sha256HexAsync(hexToBytes(meta.door_public_key))) !== meta.door_key_id) {
    process.stderr.write(
      'certify: REFUSED — ledger meta door_key_id is not sha256(door_public_key); the source identity is forged\n'
    );
    return 1;
  }

  // 1. Full chain verification first — a certificate over an invalid chain
  //    must never exist (the door key comes from the door context below, so
  //    this run is recorder-side, not third-party).
  const result = await verifyChain(entries, { doorPublicKey: meta.door_public_key });
  if (!result.ok) {
    process.stderr.write(
      `certify: REFUSED — chain verification failed at seq ${result.failure.seq ?? '?'}: ` +
        `[${result.failure.code}] ${result.failure.reason}\n`
    );
    return 1;
  }
  if (result.entries === 0) {
    process.stderr.write('certify: REFUSED — an empty ledger has nothing to certify\n');
    return 1;
  }

  const entryHashes = (entries as { entry_hash: string }[]).map((entry) => entry.entry_hash);
  const tree = await computeTreeHead(entryHashes);

  // 2. The witnessed head — REQUIRED. Without independent witnessing the
  //    "heads match witnessed history" line would be self-attested theater.
  const witnessed = await fetchVerifiedWitnessedHead({
    url: options.witnessUrl,
    sourceId: meta.door_key_id,
    witnessPublicKeyHex: options.witnessPublicKeyHex,
  });
  if (witnessed === null) {
    process.stderr.write(
      'certify: REFUSED — the witness has no head history for this ledger; stream heads first\n'
    );
    return 1;
  }
  const { record, ack } = witnessed;

  if (record.head.size > tree.size) {
    process.stderr.write(
      `certify: REFUSED — the witness recorded head size ${record.head.size} but the local ledger has ` +
        `${tree.size} entries; this chain is truncated (run 'mandare verify --witness' for detail)\n`
    );
    return 1;
  }
  if (record.head.size === tree.size && record.head.root !== tree.root) {
    process.stderr.write('certify: REFUSED — witnessed head conflicts with the local chain (fork)\n');
    return 1;
  }
  const witnessProof =
    record.head.size === tree.size || record.head.size === 0
      ? []
      : await consistencyProof(entryHashes, record.head.size);
  // Prove — not assume — that the local chain extends the witnessed head
  // append-only. A prefix-rewritten-then-grown ledger has size > witnessed
  // but is a FORK; certify must refuse it here, not ship a certificate whose
  // consistency check fails in the auditor's hands (review S6-M5).
  if (
    record.head.size !== tree.size &&
    record.head.size !== 0 &&
    !(await verifyConsistency({
      size1: record.head.size,
      root1: record.head.root,
      size2: tree.size,
      root2: tree.root,
      proof: witnessProof,
    }))
  ) {
    process.stderr.write(
      "certify: REFUSED — the local chain is NOT an append-only extension of the witnessed head (fork); run 'mandare verify --witness' for detail\n"
    );
    return 1;
  }

  // 3. Disclosures: owner-selected entries + their inclusion proofs.
  const disclosed: { seq: number; entry: LedgerEntryV1; inclusion_proof: string[] }[] = [];
  for (const seq of options.discloseSeqs) {
    if (seq < 1 || seq > tree.size) {
      process.stderr.write(`certify: REFUSED — --disclose seq ${seq} is out of range (1..${tree.size})\n`);
      return 1;
    }
    const entry = entries[seq - 1];
    if (!isLedgerEntry(entry)) {
      process.stderr.write(`certify: REFUSED — entry ${seq} fails schema validation\n`);
      return 1;
    }
    disclosed.push({ seq, entry, inclusion_proof: await inclusionProof(entryHashes, seq - 1) });
  }

  // 4. Public anchoring (best available): the latest epoch that includes one
  //    of this source's witnessed heads, with its aggregate inclusion proof —
  //    locally re-verified before it is embedded (a lying witness dies here).
  const anchor = await fetchAnchorInclusion(
    options.witnessUrl,
    meta.door_key_id,
    entryHashes,
    tree.size,
    tree.root,
    options.witnessPublicKeyHex
  );

  // 5. The IETF status list (S3), published unchanged.
  const replayed = [...(await replayRevocation(entries)).values()];
  const revocation =
    replayed.length === 0
      ? null
      : (() => {
          const payload = buildStatusListPayload({
            listId: AGENT_STATUS_LIST_ID,
            slots: replayed.map((r) => ({ index: r.statusIndex, revoked: r.revoked })),
            issuer: 'mandare:local',
            iat: Math.floor(Date.now() / 1000),
          });
          return { bits: payload.status_list.bits, lst: payload.status_list.lst };
        })();

  // 6. Sign the bundle with the door key (resolved exactly as the gateway
  //    resolves it — vault or legacy PEM). The door id comes from the ledger
  //    itself: certify signs FOR this ledger, whatever the env says.
  const ctx = await openDoorContext(env, { dbPath, doorId: meta.door_id });
  try {
    if (ctx.ledger.doorKeyId !== meta.door_key_id) {
      process.stderr.write('certify: REFUSED — resolved door key does not match the ledger meta\n');
      return 1;
    }
    const certificate = await buildIntegrityCertificate({
      ledger: {
        door_id: meta.door_id,
        door_key_id: meta.door_key_id,
        door_public_key: meta.door_public_key,
      },
      treeHead: tree,
      entryCount: result.entries,
      witness: {
        record,
        ack,
        consistency_proof: witnessProof,
      },
      anchor,
      disclosed,
      revocation,
      signer: ctx.ledger.signer(),
    });
    const rendered = `${JSON.stringify(certificate, null, 2)}\n`;
    if (options.outPath !== undefined) {
      await writeFile(options.outPath, rendered, 'utf8');
    }
    const summary = [
      `certificate: ${options.outPath ?? '(stdout)'}`,
      `ledger:      ${meta.door_id} — ${result.entries} entries, tree ${tree.size}:${tree.root.slice(0, 12)}…`,
      `witnessed:   head ${record.head.size}:${record.head.root.slice(0, 12)}… @ ${record.witnessed_at}`,
      `anchored:    ${
        anchor === null
          ? 'no (no epoch covers this source yet — certificate states witnessing only)'
          : `epoch ${anchor.inclusion.epoch.epoch} via ${anchor.inclusion.epoch.anchor_kind ?? 'none'} (${anchor.inclusion.epoch.anchor_status})`
      }`,
      `disclosed:   ${disclosed.length} entr${disclosed.length === 1 ? 'y' : 'ies'} (selective disclosure — everything else stays salted hashes)`,
    ];
    if (options.json === true) {
      process.stdout.write(rendered);
    } else {
      process.stdout.write(`${summary.join('\n')}\n`);
      if (options.outPath === undefined) {
        process.stdout.write(rendered);
      }
    }
    return 0;
  } finally {
    await closeDoorContext(ctx);
  }
}

/** Latest epoch inclusion for this source, re-verified locally; null when unanchored. */
async function fetchAnchorInclusion(
  witnessUrl: string,
  sourceId: string,
  entryHashes: string[],
  treeSize: number,
  treeRoot: string,
  witnessPublicKeyHex: string
): Promise<IntegrityCertificate['anchor']> {
  let inclusion: EpochInclusion;
  try {
    const latest = await fetch(`${witnessUrl}/v1/epochs/latest`, { signal: AbortSignal.timeout(3000) });
    if (!latest.ok) return null;
    const epoch = (await latest.json()) as { epoch: number };
    const response = await fetch(`${witnessUrl}/v1/epochs/${epoch.epoch}/inclusion/${sourceId}`, {
      signal: AbortSignal.timeout(3000),
    });
    if (!response.ok) return null;
    inclusion = parseEpochInclusion(await response.json());
  } catch {
    return null;
  }
  // The epoch must be witness-signed (a fabricated aggregate is not anchoring)
  // and the leaf must be a verifiably included head of THIS source that the
  // certified tree extends append-only. Anything short of that: leave the
  // certificate unanchored rather than embed a proof that won't verify.
  const epochSigned = await verifyEpochSummary(inclusion.epoch, witnessPublicKeyHex);
  const included =
    epochSigned &&
    (await verifyAggregateInclusion({
      record: inclusion.leaf,
      leafIndex: inclusion.leaf_index,
      aggregate: inclusion.epoch.aggregate,
      proof: inclusion.inclusion_proof,
    }));
  if (!included || inclusion.leaf.source_id !== sourceId || inclusion.leaf.head.size > treeSize) {
    return null;
  }
  const proof =
    inclusion.leaf.head.size === treeSize || inclusion.leaf.head.size === 0
      ? []
      : await consistencyProof(entryHashes, inclusion.leaf.head.size);
  if (
    inclusion.leaf.head.size !== treeSize &&
    inclusion.leaf.head.size !== 0 &&
    !(await verifyConsistency({
      size1: inclusion.leaf.head.size,
      root1: inclusion.leaf.head.root,
      size2: treeSize,
      root2: treeRoot,
      proof,
    }))
  ) {
    return null;
  }
  if (inclusion.leaf.head.size === treeSize && inclusion.leaf.head.root !== treeRoot) {
    return null;
  }
  return { inclusion, consistency_proof: proof };
}

export interface CertifyVerifyOptions {
  witnessPublicKeyHex: string;
  doorPublicKeyHex?: string;
  json?: boolean;
}

/** Third-party verification: file in, verdict out — no ledger, no services. */
export async function runCertifyVerify(
  filePath: string,
  options: CertifyVerifyOptions
): Promise<number> {
  let certificate;
  try {
    certificate = parseIntegrityCertificate(JSON.parse(await readFile(filePath, 'utf8')));
  } catch (error) {
    process.stderr.write(
      `certify verify: not a valid certificate — ${error instanceof Error ? error.message : String(error)}\n`
    );
    return 1;
  }
  const verdict = await verifyIntegrityCertificate(certificate, {
    witnessPublicKeyHex: options.witnessPublicKeyHex,
    ...(options.doorPublicKeyHex === undefined ? {} : { doorPublicKeyHex: options.doorPublicKeyHex }),
  });
  if (options.json === true) {
    process.stdout.write(`${JSON.stringify(verdict, null, 2)}\n`);
  } else {
    for (const check of verdict.checks) {
      // A failing PROOF check is a real FAIL; a not-yet-final recorder-
      // attested check (e.g. anchoring still pending) is a NOTE, never a
      // failure of an otherwise-sound certificate.
      const mark = check.ok ? 'PASS' : check.basis === 'proof' ? 'FAIL' : 'NOTE';
      const basis = check.basis === 'proof' ? '' : ' [recorder-attested]';
      process.stdout.write(`${mark}  ${check.name}${basis}: ${check.detail}\n`);
    }
    process.stdout.write(
      verdict.ok
        ? 'certificate: VALID — every proof-backed check verified\n'
        : 'certificate: INVALID — at least one check failed\n'
    );
  }
  return verdict.ok ? 0 : 1;
}
