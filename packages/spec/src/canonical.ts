/**
 * Deterministic canonical JSON serialization (JCS-flavored, RFC 8785 subset).
 *
 * Invariants:
 * - Object keys sorted by UTF-16 code units (RFC 8785 §3.2.3).
 * - No whitespace; numbers serialized via ECMAScript `JSON.stringify` rules.
 * - Object properties with `undefined` values are dropped (mirrors JSON.stringify).
 * - Rejected outright: non-finite numbers, bigint, functions, symbols,
 *   `undefined` inside arrays, and non-plain objects (Date, Map, class
 *   instances…) — callers must pre-serialize those to JSON-native values.
 *
 * This function is the ONLY serialization allowed as hash input anywhere in
 * Mandare. Two implementations that disagree here would produce diverging
 * entry hashes, so treat any behavior change as a frozen-contract change
 * (schema version bump + TASKS.md decision entry).
 */
export function canonicalJson(value: unknown): string {
  if (value === undefined) {
    throw new TypeError('cannot canonicalize undefined');
  }
  return serialize(value, 'value');
}

function serialize(value: unknown, path: string): string {
  if (value === null) {
    return 'null';
  }
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new TypeError(`non-finite number at ${path}`);
      }
      return JSON.stringify(value);
    case 'object':
      return Array.isArray(value)
        ? serializeArray(value, path)
        : serializeObject(value as Record<string, unknown>, path);
    default:
      throw new TypeError(`cannot canonicalize ${typeof value} at ${path}`);
  }
}

function serializeArray(value: readonly unknown[], path: string): string {
  const items = value.map((item, i) => {
    if (item === undefined) {
      throw new TypeError(`undefined array element at ${path}[${i}]`);
    }
    return serialize(item, `${path}[${i}]`);
  });
  return `[${items.join(',')}]`;
}

function serializeObject(value: Record<string, unknown>, path: string): string {
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError(`non-plain object at ${path} (pre-serialize to JSON-native values)`);
  }
  const parts = Object.keys(value)
    .sort(compareUtf16)
    .filter((key) => value[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${serialize(value[key], `${path}.${key}`)}`);
  return `{${parts.join(',')}}`;
}

function compareUtf16(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
