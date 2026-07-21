import { describe, expect, test } from 'vitest';

import { canonicalJson } from '../src/canonical.js';

describe('canonicalJson', () => {
  test('sorts object keys recursively by UTF-16 code units', () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}');
  });

  test('is insensitive to key insertion order', () => {
    const first = canonicalJson({ x: 1, y: [{ b: 2, a: 3 }] });
    const second = canonicalJson({ y: [{ a: 3, b: 2 }], x: 1 });
    expect(first).toBe(second);
  });

  test('preserves array order', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]');
  });

  test('drops undefined object properties', () => {
    expect(canonicalJson({ a: 1, gone: undefined })).toBe('{"a":1}');
  });

  test('serializes primitives like JSON', () => {
    expect(canonicalJson(null)).toBe('null');
    expect(canonicalJson(true)).toBe('true');
    expect(canonicalJson('täxt "quoted"')).toBe(JSON.stringify('täxt "quoted"'));
    expect(canonicalJson(0.000015)).toBe('0.000015');
    expect(canonicalJson(1e21)).toBe('1e+21');
  });

  test('emits no whitespace', () => {
    expect(canonicalJson({ a: [1, 2], b: 's' })).not.toMatch(/\s/);
  });

  test('round-trips through JSON.parse', () => {
    const value = { z: [1, 'two', { deep: true, n: null }], a: 0.5 };
    expect(JSON.parse(canonicalJson(value))).toEqual(value);
  });

  test('rejects non-finite numbers', () => {
    expect(() => canonicalJson({ a: Number.NaN })).toThrow(TypeError);
    expect(() => canonicalJson({ a: Number.POSITIVE_INFINITY })).toThrow(TypeError);
  });

  test('rejects bigint, functions, symbols, and top-level undefined', () => {
    expect(() => canonicalJson(1n)).toThrow(TypeError);
    expect(() => canonicalJson(() => 1)).toThrow(TypeError);
    expect(() => canonicalJson(Symbol('s'))).toThrow(TypeError);
    expect(() => canonicalJson(undefined)).toThrow(TypeError);
  });

  test('rejects undefined array elements instead of nulling them', () => {
    expect(() => canonicalJson([1, undefined, 3])).toThrow(/undefined array element/);
  });

  test('rejects non-plain objects (Date, Map, class instances)', () => {
    expect(() => canonicalJson(new Date())).toThrow(/non-plain object/);
    expect(() => canonicalJson(new Map())).toThrow(/non-plain object/);
    class Thing {
      x = 1;
    }
    expect(() => canonicalJson(new Thing())).toThrow(/non-plain object/);
  });

  test('accepts null-prototype objects', () => {
    const value = Object.create(null) as Record<string, unknown>;
    value.a = 1;
    expect(canonicalJson(value)).toBe('{"a":1}');
  });
});
