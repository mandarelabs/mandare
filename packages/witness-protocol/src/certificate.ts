import { type Static, Type } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';

import {
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalJson,
  computeEntryHashAsync,
  hexToBytes,
  isLedgerEntry,
  sha256HexAsync,
  type LedgerEntryV1,
} from '@mandarelabs/spec';
import { verifyConsistency, verifyInclusion, type TreeHead } from '@mandarelabs/verifier';

import { verifyAggregateInclusion, verifyEpochSummary } from './aggregate.js';
import {
  EpochInclusion,
  SignedHeadAck,
  TreeHeadSchema,
  WitnessedHeadRecord,
  WitnessMessageError,
} from './messages.js';
import { verifySignedPayload, type HeadSigner } from './signing.js';
import { collectBitcoin, parseOtsProof } from './ots.js';

/**
 * The integrity certificate (SPEC §9.4) — the artifact an insurer/auditor
 * consumes. It states, checkably: chain valid · sequence complete · heads
 * match independently witnessed history · root publicly anchored — over
 * owner-SELECTED entries with inclusion proofs. Selective disclosure is the
 * point: the third party verifies the disclosed entries belong to the
 * witnessed, anchored history WITHOUT seeing anything else (every proof node
 * is a salted hash; SPEC §6 privacy).
 *
 * Honesty rule, applied: each check the third-party verifier runs is proof-
 * backed; the two claims it structurally CANNOT re-derive without the full
 * ledger (chain validity, gapless sequence) are labeled `recorder-attested`
 * in the verification report — they are the owner's verifier run, bounded by
 * the witness's consistency-enforced head history, not by trust in the file.
 */

export const CERTIFICATE_FORMAT = 'mandare-integrity-certificate/1';

const Sha256Hex = Type.String({ pattern: '^[0-9a-f]{64}$' });
const IsoUtc = Type.String({
  pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,3})?Z$',
});

export const IntegrityCertificateSchema = Type.Object(
  {
    format: Type.Literal(CERTIFICATE_FORMAT),
    created_at: IsoUtc,
    ledger: Type.Object(
      {
        door_id: Type.String({ minLength: 1 }),
        door_key_id: Sha256Hex,
        /** Self-declared; pass an out-of-band door key to the verifier to bind authorship. */
        door_public_key: Sha256Hex,
      },
      { additionalProperties: false }
    ),
    tree_head: TreeHeadSchema,
    /** Owner-run verifier results over the FULL ledger (recorder-attested). */
    chain: Type.Object(
      {
        entries: Type.Integer({ minimum: 0 }),
        valid: Type.Literal(true),
        sequence_complete: Type.Literal(true),
      },
      { additionalProperties: false }
    ),
    witness: Type.Object(
      {
        record: WitnessedHeadRecord,
        /** The witness's signed statement of that record (verify out-of-band). */
        ack: SignedHeadAck,
        /** RFC 6962 consistency proof: witnessed head → tree_head. */
        consistency_proof: Type.Array(Sha256Hex, { maxItems: 64 }),
      },
      { additionalProperties: false }
    ),
    /** Public anchoring of a witnessed head of this source; null while unanchored. */
    anchor: Type.Union([
      Type.Object(
        {
          inclusion: EpochInclusion,
          /** Consistency proof: anchored leaf head → tree_head (empty if equal). */
          consistency_proof: Type.Array(Sha256Hex, { maxItems: 64 }),
        },
        { additionalProperties: false }
      ),
      Type.Null(),
    ]),
    disclosed: Type.Array(
      Type.Object(
        {
          seq: Type.Integer({ minimum: 1 }),
          /** Full LedgerEntryV1 — validated against the spec schema at verify time. */
          entry: Type.Unknown(),
          inclusion_proof: Type.Array(Sha256Hex, { maxItems: 64 }),
        },
        { additionalProperties: false }
      ),
      { maxItems: 4096 }
    ),
    /**
     * The IETF Token Status List bitstring rendered from the ledger's
     * revocation projection (S3) — published UNCHANGED, as designed.
     */
    revocation: Type.Union([
      Type.Object(
        { bits: Type.Integer({ minimum: 1, maximum: 8 }), lst: Type.String({ maxLength: 4 * 1024 * 1024 }) },
        { additionalProperties: false }
      ),
      Type.Null(),
    ]),
    residuals: Type.Array(Type.String()),
    /** Door signature over sha256(canonicalJson(certificate minus this field)). */
    signature: Type.Object(
      { key_id: Sha256Hex, value: Type.String({ pattern: '^[A-Za-z0-9_-]{86}$' }) },
      { additionalProperties: false }
    ),
  },
  { additionalProperties: false }
);
export type IntegrityCertificate = Static<typeof IntegrityCertificateSchema>;

/** The residuals every certificate carries — stated, never hidden (SPEC §6). */
export const CERTIFICATE_RESIDUALS = [
  'A full-machine-root attacker acting entirely outside the Mandare doors was never in claimed coverage.',
  'Entries appended after the witnessed head shown here are covered only from the next witnessed head onward.',
  'chain.valid and chain.sequence_complete are the recorder-side verifier run over the full ledger; a third party re-derives them only with full-ledger access.',
];

export function parseIntegrityCertificate(value: unknown): IntegrityCertificate {
  if (Value.Check(IntegrityCertificateSchema, value)) {
    return value;
  }
  const errors = [...Value.Errors(IntegrityCertificateSchema, value)].map(
    (e) => `${e.path || '/'}: ${e.message}`
  );
  throw new WitnessMessageError('IntegrityCertificate', errors);
}

export interface BuildCertificateArgs {
  ledger: { door_id: string; door_key_id: string; door_public_key: string };
  treeHead: TreeHead;
  entryCount: number;
  witness: IntegrityCertificate['witness'];
  anchor: IntegrityCertificate['anchor'];
  disclosed: { seq: number; entry: LedgerEntryV1; inclusion_proof: string[] }[];
  revocation: { bits: number; lst: string } | null;
  signer: HeadSigner;
  createdAt?: string;
}

/** Assemble and door-sign a certificate. Callers supply already-built proofs. */
export async function buildIntegrityCertificate(
  args: BuildCertificateArgs
): Promise<IntegrityCertificate> {
  const unsigned = {
    format: CERTIFICATE_FORMAT,
    created_at: args.createdAt ?? new Date().toISOString(),
    ledger: args.ledger,
    tree_head: args.treeHead,
    chain: { entries: args.entryCount, valid: true as const, sequence_complete: true as const },
    witness: args.witness,
    anchor: args.anchor,
    disclosed: args.disclosed,
    revocation: args.revocation,
    residuals: [...CERTIFICATE_RESIDUALS],
  };
  const digest = hexToBytes(await sha256HexAsync(canonicalJson(unsigned)));
  const signature = bytesToBase64Url(await args.signer.sign(digest));
  return parseIntegrityCertificate({
    ...unsigned,
    signature: { key_id: args.signer.keyId, value: signature },
  });
}

export interface CertificateCheck {
  name: string;
  ok: boolean;
  /** 'proof' = re-derived here; 'recorder-attested' = owner's verifier run. */
  basis: 'proof' | 'recorder-attested';
  detail: string;
}

export interface CertificateVerifyResult {
  ok: boolean;
  checks: CertificateCheck[];
}

export interface VerifyCertificateOptions {
  /** The witness public key, obtained OUT-OF-BAND. Required — see below. */
  witnessPublicKeyHex: string;
  /** Out-of-band door key (hex). Absent ⇒ the certificate's own key is used (weaker, reported). */
  doorPublicKeyHex?: string;
}

async function verifyEd25519(
  publicKeyHex: string,
  signatureB64Url: string,
  data: Uint8Array
): Promise<boolean> {
  try {
    const key = await globalThis.crypto.subtle.importKey(
      'raw',
      hexToBytes(publicKeyHex) as Uint8Array<ArrayBuffer>,
      { name: 'Ed25519' },
      false,
      ['verify']
    );
    return await globalThis.crypto.subtle.verify(
      { name: 'Ed25519' },
      key,
      base64UrlToBytes(signatureB64Url) as Uint8Array<ArrayBuffer>,
      data as Uint8Array<ArrayBuffer>
    );
  } catch {
    return false;
  }
}

/**
 * Third-party verification: everything provable from the certificate alone
 * is re-derived here — no ledger access, no Mandare service, no trust in the
 * file's own claims beyond what each check states.
 */
export async function verifyIntegrityCertificate(
  certificate: IntegrityCertificate,
  options: VerifyCertificateOptions
): Promise<CertificateVerifyResult> {
  const checks: CertificateCheck[] = [];
  const push = (check: CertificateCheck) => checks.push(check);

  // 1. Bundle signature: the recorder signed this exact certificate.
  //    The whole protocol rests on source_id == sha256(door public key)
  //    (the witness enforces it on every submission), so the verifier must
  //    hold the certificate to the SAME invariant — otherwise self-declared
  //    mode lets an attacker name a victim's source_id while signing with
  //    their own key and impersonate the victim's witnessed history (review
  //    S6-H1). Binding door_public_key → door_key_id forces the impersonator
  //    to use the victim's key, at which point the bundle signature fails.
  const { signature, ...unsigned } = certificate;
  const doorKey = options.doorPublicKeyHex ?? certificate.ledger.door_public_key;
  const doorKeyId = await sha256HexAsync(hexToBytes(doorKey));
  const declaredKeyBindsSource =
    (await sha256HexAsync(hexToBytes(certificate.ledger.door_public_key))) ===
    certificate.ledger.door_key_id;
  // The witness, consistency, and anchor checks (2, 3, 5) are ALL bound to
  // certificate.ledger.door_key_id — the SOURCE identity. Binding only the
  // bundle signature to the trusted key (out-of-band mode) is not enough: a
  // key-holding operator could witness a curated/truncated tree under a FRESH
  // source_id, self-declare that source in the certificate, and still sign the
  // bundle with the trusted door key — passing verification while the
  // witnessed/anchored history belongs to a parallel source the auditor never
  // meant to audit (S8/C1). Require the certified source to BE the trusted key:
  // door_key_id == sha256(doorKey). In self-declared mode this is exactly
  // declaredKeyBindsSource (doorKey == door_public_key), so it is a no-op there
  // and only tightens the stronger out-of-band path.
  const sourceBindsDoorKey = certificate.ledger.door_key_id === doorKeyId;
  const digest = await bundleDigest(unsigned);
  const bundleOk =
    declaredKeyBindsSource &&
    sourceBindsDoorKey &&
    signature.key_id === doorKeyId &&
    (await verifyEd25519(doorKey, signature.value, digest));
  push({
    name: 'bundle-signature',
    ok: bundleOk,
    basis: 'proof',
    detail: bundleOk
      ? options.doorPublicKeyHex !== undefined
        ? 'certificate signed by the out-of-band door key, which is also the certified source'
        : 'certificate signed by its self-declared door key (pass an out-of-band key to bind authorship)'
      : !declaredKeyBindsSource
        ? 'ledger.door_key_id is not sha256(ledger.door_public_key) — the source identity is forged'
        : !sourceBindsDoorKey
          ? 'certified source (ledger.door_key_id) is not the out-of-band door key — the witnessed history belongs to a different source'
          : 'certificate signature INVALID — the bundle was altered or the key is wrong',
  });

  // 2. Witnessed head: the witness's signature over the head history entry.
  const { record, ack, consistency_proof } = certificate.witness;
  const ackSigOk = await verifySignedPayload(ack, options.witnessPublicKeyHex);
  const ackBindsRecord =
    ack.payload.source_id === record.source_id &&
    ack.payload.source_id === certificate.ledger.door_key_id &&
    ack.payload.head.size === record.head.size &&
    ack.payload.head.root === record.head.root;
  push({
    name: 'witnessed-head-signature',
    ok: ackSigOk && ackBindsRecord,
    basis: 'proof',
    detail:
      ackSigOk && ackBindsRecord
        ? `witness signed head ${record.head.size}:${record.head.root.slice(0, 12)}… for this source`
        : 'witnessed head is not validly signed by the supplied witness key',
  });

  // 3. Consistency: the certified tree extends the witnessed head append-only.
  let consistencyOk: boolean;
  if (record.head.size > certificate.tree_head.size) {
    consistencyOk = false;
  } else if (record.head.size === certificate.tree_head.size) {
    consistencyOk = record.head.root === certificate.tree_head.root && consistency_proof.length === 0;
  } else {
    consistencyOk = await verifyConsistency({
      size1: record.head.size,
      root1: record.head.root,
      size2: certificate.tree_head.size,
      root2: certificate.tree_head.root,
      proof: consistency_proof,
    });
  }
  push({
    name: 'witnessed-consistency',
    ok: consistencyOk,
    basis: 'proof',
    detail: consistencyOk
      ? `certified tree (${certificate.tree_head.size}) extends the witnessed head (${record.head.size}) append-only`
      : 'certified tree does NOT extend the witnessed head — truncation or rewrite',
  });

  // 4. Disclosed entries: schema + entry hash + door signature + inclusion.
  for (const disclosure of certificate.disclosed) {
    const name = `disclosed-entry-seq-${disclosure.seq}`;
    const entry = disclosure.entry;
    if (!isLedgerEntry(entry)) {
      push({ name, ok: false, basis: 'proof', detail: 'disclosed entry fails the LedgerEntryV1 schema' });
      continue;
    }
    if (entry.seq !== disclosure.seq) {
      push({ name, ok: false, basis: 'proof', detail: 'disclosed entry seq does not match its slot' });
      continue;
    }
    const { entry_hash, door_signature, ...preimage } = entry;
    const recomputed = await computeEntryHashAsync(preimage);
    if (recomputed !== entry_hash) {
      push({ name, ok: false, basis: 'proof', detail: 'entry content does not match its hash' });
      continue;
    }
    const signatureOk = await verifyEd25519(doorKey, door_signature.value, hexToBytes(entry_hash));
    if (!signatureOk) {
      push({ name, ok: false, basis: 'proof', detail: 'door signature on the entry is invalid' });
      continue;
    }
    const included = await verifyInclusion({
      index: disclosure.seq - 1,
      treeSize: certificate.tree_head.size,
      entryHash: entry_hash,
      proof: disclosure.inclusion_proof,
      root: certificate.tree_head.root,
    });
    push({
      name,
      ok: included,
      basis: 'proof',
      detail: included
        ? `entry ${disclosure.seq} verifiably included in the certified tree`
        : 'inclusion proof does NOT reach the certified root',
    });
  }

  // 5. Public anchoring — split into two honest claims (review S6-H2):
  //    (a) the aggregation is PROVABLE: the epoch is witness-signed (so the
  //        aggregate root is the witness's, not fabricated), the leaf is a
  //        witnessed head of THIS source included in it, and a prefix of the
  //        certified tree;
  //    (b) whether the aggregate reached a PUBLIC CHAIN is reported from the
  //        anchor receipt — 'proof' basis ONLY when a Bitcoin attestation
  //        actually verifies; otherwise it is pending/recorder-attested,
  //        never overclaimed.
  if (certificate.anchor !== null) {
    const { inclusion, consistency_proof: anchorProof } = certificate.anchor;
    const leaf = inclusion.leaf;
    const sourceOk = leaf.source_id === certificate.ledger.door_key_id;
    const epochSigned = await verifyEpochSummary(inclusion.epoch, options.witnessPublicKeyHex);
    const leafIncluded =
      sourceOk &&
      epochSigned &&
      (await verifyAggregateInclusion({
        record: leaf,
        leafIndex: inclusion.leaf_index,
        aggregate: inclusion.epoch.aggregate,
        proof: inclusion.inclusion_proof,
      }));
    let leafConsistent: boolean;
    if (leaf.head.size > certificate.tree_head.size) {
      leafConsistent = false;
    } else if (leaf.head.size === certificate.tree_head.size) {
      leafConsistent = leaf.head.root === certificate.tree_head.root && anchorProof.length === 0;
    } else {
      leafConsistent = await verifyConsistency({
        size1: leaf.head.size,
        root1: leaf.head.root,
        size2: certificate.tree_head.size,
        root2: certificate.tree_head.root,
        proof: anchorProof,
      });
    }
    const aggregationOk = leafIncluded && leafConsistent;
    push({
      name: 'witness-aggregated-head',
      ok: aggregationOk,
      basis: 'proof',
      detail: aggregationOk
        ? `witnessed head ${leaf.head.size}:${leaf.head.root.slice(0, 12)}… is witness-signed leaf ${inclusion.leaf_index} of epoch ${inclusion.epoch.epoch}`
        : !sourceOk
          ? 'anchored leaf belongs to a DIFFERENT source'
          : !epochSigned
            ? 'epoch aggregate is NOT witness-signed — refusing an unattested aggregate root'
            : !leafIncluded
              ? 'aggregate inclusion proof is invalid'
              : 'anchored head is not a prefix of the certified tree',
    });

    // (b) Public-chain finality — 'proof' ONLY on a verified Bitcoin
    //     attestation. A receipt that CLAIMS OTS but does not commit the
    //     epoch root (or is unparseable) is an active lie → basis 'proof',
    //     fails the verdict. Pending OTS, non-public adapters (mock), and no
    //     receipt are honest non-final states → 'recorder-attested',
    //     reported but not gating.
    let anchorOk = false;
    let anchorBasis: CertificateCheck['basis'] = 'recorder-attested';
    let anchorDetail: string;
    if (inclusion.epoch.ots_base64 !== null && inclusion.epoch.anchor_kind === 'opentimestamps') {
      try {
        const proof = await parseOtsProof(base64UrlToBytes(inclusion.epoch.ots_base64));
        const commitsRoot = digestEquals(proof.digest, inclusion.epoch.aggregate.root);
        if (commitsRoot && collectBitcoin(proof.timestamp).length > 0) {
          // The receipt commits the epoch root AND carries a Bitcoin attestation
          // tag — but confirming that attestation names a REAL, confirmed block
          // requires a Bitcoin node/header lookup, which this OFFLINE verifier
          // cannot do. The tag's mere presence is NOT public-chain finality: a
          // witness-key holder (solo topology) can fabricate an attestation tag
          // committing any digest (S8/C2). Report it honestly as
          // recorder-attested and tell the relying party to verify the .ots
          // against a chain — never GATE the verdict on a finality claim this
          // verifier could not check. (proof-basis is reserved for what is
          // re-derived here: a receipt that does NOT commit the root, or is
          // unparseable, remains a proof-basis failure below — those ARE
          // offline-detectable lies.)
          anchorOk = true;
          anchorBasis = 'recorder-attested';
          anchorDetail =
            'OpenTimestamps receipt commits the epoch root and declares a Bitcoin attestation — ' +
            'verify the .ots against a Bitcoin node/explorer to confirm finality (not checkable offline)';
        } else if (commitsRoot) {
          anchorDetail = 'OpenTimestamps proof commits the epoch root but is still PENDING Bitcoin confirmation (hours)';
        } else {
          anchorBasis = 'proof';
          anchorDetail = 'OpenTimestamps receipt does NOT commit the epoch aggregate root — forged/mismatched';
        }
      } catch (error) {
        anchorBasis = 'proof';
        anchorDetail = `OpenTimestamps receipt unparseable: ${error instanceof Error ? error.message : 'error'}`;
      }
    } else if (inclusion.epoch.anchor_kind !== null) {
      anchorDetail = `anchor adapter '${inclusion.epoch.anchor_kind}' (${inclusion.epoch.anchor_status}) — NOT a verified public-chain proof`;
    } else {
      anchorDetail = 'aggregate not yet anchored to a public chain';
    }
    push({ name: 'public-anchor', ok: anchorOk, basis: anchorBasis, detail: anchorDetail });
  }

  // 6. The recorder-attested claims — labeled, never silently trusted.
  push({
    name: 'chain-valid-and-complete',
    ok: certificate.chain.valid && certificate.chain.sequence_complete,
    basis: 'recorder-attested',
    detail:
      `the recorder's verifier reported ${certificate.chain.entries} entries, chain valid, ` +
      'sequence gapless — re-derivable only with full-ledger access; bounded by the witnessed history above',
  });

  // The verdict gates on PROOF-basis checks only: those are re-derived here
  // and a failing one is an active contradiction (forged signature, tampered
  // entry, unattested aggregate, lying receipt). recorder-attested checks are
  // reported honestly but are non-final by nature (chain validity needs the
  // full ledger; public anchoring may be legitimately pending) — they never
  // silently pass, and they never fail a certificate that is otherwise sound.
  const ok = checks.filter((check) => check.basis === 'proof').every((check) => check.ok);
  return { ok, checks };
}

async function bundleDigest(unsigned: Omit<IntegrityCertificate, 'signature'>): Promise<Uint8Array> {
  return hexToBytes(await sha256HexAsync(canonicalJson(unsigned)));
}

/** Byte equality between a digest and its expected hex (both pre-validated). */
function digestEquals(digest: Uint8Array, rootHex: string): boolean {
  const root = hexToBytes(rootHex);
  if (digest.length !== root.length) return false;
  let diff = 0;
  for (let i = 0; i < digest.length; i += 1) diff |= (digest[i] as number) ^ (root[i] as number);
  return diff === 0;
}
