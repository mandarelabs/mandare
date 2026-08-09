import {
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalJson,
  hexToBytes,
  sha256HexAsync,
} from '@mandarelabs/spec';

/**
 * Message signing for the witness protocol. Same construction as ledger
 * entries: Ed25519 over sha256(canonicalJson(payload)) — one signing rule
 * across the whole stack, WebCrypto only (portable, embeddable).
 */

/**
 * Anything that can sign a 32-byte digest with an Ed25519 key. The ledger's
 * `DoorKey` satisfies this structurally — the interface is duplicated here
 * (rather than imported) so this Apache package never depends on AGPL code.
 */
export interface HeadSigner {
  /** sha256 hex of the raw 32-byte public key. */
  readonly keyId: string;
  /** Raw 32-byte public key, lowercase hex. */
  readonly publicKeyHex: string;
  sign(data: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export interface SignedMessage<T> {
  payload: T;
  /** Ed25519 signature over sha256(canonicalJson(payload)), base64url. */
  signature: string;
}

async function payloadDigest(payload: unknown): Promise<Uint8Array> {
  return hexToBytes(await sha256HexAsync(canonicalJson(payload)));
}

export async function signPayload<T>(payload: T, signer: HeadSigner): Promise<SignedMessage<T>> {
  const signature = await signer.sign(await payloadDigest(payload));
  return { payload, signature: bytesToBase64Url(signature) };
}

/**
 * Verify a signed protocol message against a raw Ed25519 public key (hex).
 * Returns false on ANY malformation — a verification path never throws on
 * hostile input, it just refuses (R4).
 */
export async function verifySignedPayload(
  message: SignedMessage<unknown>,
  publicKeyHex: string
): Promise<boolean> {
  try {
    const key = await globalThis.crypto.subtle.importKey(
      'raw',
      hexToBytes(publicKeyHex) as Uint8Array<ArrayBuffer>,
      { name: 'Ed25519' },
      false,
      ['verify']
    );
    const digest = await payloadDigest(message.payload);
    return await globalThis.crypto.subtle.verify(
      { name: 'Ed25519' },
      key,
      base64UrlToBytes(message.signature) as Uint8Array<ArrayBuffer>,
      digest as Uint8Array<ArrayBuffer>
    );
  } catch {
    return false;
  }
}
