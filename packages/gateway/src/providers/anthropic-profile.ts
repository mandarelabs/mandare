import { asRecord, PLAIN_TEXT_PROFILE, type ProfileResult } from './types.js';

/**
 * What an Anthropic Messages request can be billed for beyond its own bytes
 * (S-2). Sources, platform.claude.com as of 2026-09: /about-claude/pricing
 * ("Tool use pricing", "Specific tool pricing", "Prompt caching", "Data
 * residency pricing") and /build-with-claude/vision ("Resolution and token
 * cost").
 */

/** Claude 4.7+ caps an image at 4,784 visual tokens (standard tier: 1,568), whatever its source. */
export const ANTHROPIC_IMAGE_TOKENS_MAX = 4_784;

/** `inference_geo: "us"` bills every token category at 1.1× (Claude 4.6+). */
const US_INFERENCE_MULTIPLIER = 1.1;

/**
 * Client-side built-in tools cost tokens only (no per-use fee): a fixed
 * definition + system-prompt overhead, rounded up here. Longest prefix first.
 * Everything else with a `type` — web search/fetch, code execution, MCP
 * toolsets, tools this code has never seen — carries per-use fees or injects
 * content the door cannot bound, and is refused.
 */
const CLIENT_TOOL_OVERHEAD: readonly (readonly [prefix: string, tokens: number])[] = [
  ['computer_toolset_', 8_192], // ~4,500–4,590 tokens incl. its tool-use system prompt
  ['browser_toolset_', 8_192], // ~6,600–6,670, +~880 with every optional member
  ['computer_', 2_048], // 466–499 system-prompt tokens + ~735 per definition
  ['text_editor_', 1_024], // 700 tokens
  ['bash_', 1_024], // 244–325 tokens
];

/** Blocks whose billed tokens their own bytes bound. */
const TEXT_BLOCKS: ReadonlySet<string> = new Set(['text', 'tool_use', 'thinking']);

/** tool_result → search_result → text is the deepest legitimate nesting. */
const MAX_CONTENT_DEPTH = 4;

interface Tally {
  images: number;
  fixedInputTokens: number;
  unsizedInput: boolean;
}

export function profileAnthropicRequest(body: Readonly<Record<string, unknown>>): ProfileResult {
  const tally: Tally = { images: 0, fixedInputTokens: 0, unsizedInput: false };
  const refusal =
    profileTools(body.tools, tally) ??
    profileContent(body.system, tally, 0) ??
    firstRefusal(messageContents(body.messages), (content) => profileContent(content, tally, 0));
  if (refusal !== null) {
    return { ok: false, reason: refusal };
  }
  return {
    ok: true,
    profile: {
      ...PLAIN_TEXT_PROFILE,
      ...tally,
      cacheWrite: requestedCacheWrite(body),
      priceMultiplier: body.inference_geo === 'us' ? US_INFERENCE_MULTIPLIER : 1,
    },
  };
}

function profileTools(tools: unknown, tally: Tally): string | null {
  if (!Array.isArray(tools)) {
    return null;
  }
  for (const tool of tools) {
    const type = asRecord(tool)?.type;
    if (type === undefined || type === 'custom') {
      continue; // a custom tool is text: its bytes bound it
    }
    const overhead =
      typeof type === 'string'
        ? CLIENT_TOOL_OVERHEAD.find(([prefix]) => type.startsWith(prefix))
        : undefined;
    if (overhead === undefined) {
      return `tool type '${String(type).slice(0, 64)}' is a server-side or unknown tool — per-use fees and injected content this door cannot bound (fail-closed)`;
    }
    tally.fixedInputTokens += overhead[1];
  }
  return null;
}

function profileContent(content: unknown, tally: Tally, depth: number): string | null {
  if (!Array.isArray(content)) {
    return null; // a string (or nothing): its bytes bound it
  }
  if (depth > MAX_CONTENT_DEPTH) {
    return 'content nested deeper than any Anthropic block allows (fail-closed)';
  }
  return firstRefusal(content, (block) => profileBlock(block, tally, depth));
}

function profileBlock(block: unknown, tally: Tally, depth: number): string | null {
  const record = asRecord(block);
  const type = record?.type;
  if (record === null || typeof type !== 'string' || TEXT_BLOCKS.has(type)) {
    // Malformed blocks are rejected by the provider unbilled.
    return null;
  }
  switch (type) {
    case 'image':
      tally.images += 1;
      return null;
    case 'document':
      return profileDocument(asRecord(record.source), tally, depth);
    case 'tool_result':
    case 'search_result':
      return profileContent(record.content, tally, depth + 1);
    case 'redacted_thinking':
      // Encrypted: billed by its plaintext, which its bytes do not bound.
      tally.unsizedInput = true;
      return null;
    default:
      return `content block type '${type.slice(0, 64)}' is not metered by this door — server-tool results, uploads and unknown blocks are refused (fail-closed)`;
  }
}

function profileDocument(
  source: Record<string, unknown> | null,
  tally: Tally,
  depth: number
): string | null {
  if (source?.type === 'text') {
    return null;
  }
  if (source?.type === 'content') {
    return profileContent(source.content, tally, depth + 1);
  }
  // A PDF (inline, by URL or by file id): pages — and so tokens — unknown.
  tally.unsizedInput = true;
  return null;
}

/**
 * Any `cache_control` anywhere asks for a cache write (block-level
 * breakpoints, or automatic caching at the top level); a 1-hour TTL is
 * billed at 2× input, the 5-minute default at 1.25×.
 */
function requestedCacheWrite(body: Readonly<Record<string, unknown>>): 'none' | '5m' | '1h' {
  let found: 'none' | '5m' = 'none';
  const pending: unknown[] = [body];
  while (pending.length > 0) {
    const next = pending.pop();
    if (Array.isArray(next)) {
      for (const item of next) pending.push(item);
      continue;
    }
    const record = asRecord(next);
    if (record === null) {
      continue;
    }
    if ('cache_control' in record) {
      if (asRecord(record.cache_control)?.ttl === '1h') {
        return '1h';
      }
      found = '5m';
    }
    for (const value of Object.values(record)) pending.push(value);
  }
  return found;
}

function messageContents(messages: unknown): unknown[] {
  return Array.isArray(messages) ? messages.map((message) => asRecord(message)?.content) : [];
}

function firstRefusal<T>(items: readonly T[], check: (item: T) => string | null): string | null {
  for (const item of items) {
    const refusal = check(item);
    if (refusal !== null) {
      return refusal;
    }
  }
  return null;
}
