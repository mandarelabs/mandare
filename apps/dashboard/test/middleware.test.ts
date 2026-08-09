import { describe, expect, it } from 'vitest';

import { hostnameOf, isHostAllowed } from '../src/middleware';

describe('dashboard Host allowlist (DNS-rebinding defense)', () => {
  it('loopback names pass, with or without ports', () => {
    for (const host of ['127.0.0.1', '127.0.0.1:8788', 'localhost:8788', '[::1]:8788']) {
      expect(isHostAllowed(host, '')).toBe(true);
    }
  });

  it('a rebound attacker hostname is refused', () => {
    expect(isHostAllowed('evil.attacker.example', '')).toBe(false);
    expect(isHostAllowed('evil.attacker.example:8788', '')).toBe(false);
  });

  it('missing Host is refused (strict)', () => {
    expect(isHostAllowed(null, '')).toBe(false);
    expect(isHostAllowed('', '')).toBe(false);
  });

  it('operator-declared extra hosts pass', () => {
    expect(isHostAllowed('fleet.internal:8788', 'fleet.internal, other.example')).toBe(true);
    expect(isHostAllowed('other.example', 'fleet.internal, other.example')).toBe(true);
    expect(isHostAllowed('third.example', 'fleet.internal, other.example')).toBe(false);
  });

  it('IPv6 host parsing keeps the bracket form', () => {
    expect(hostnameOf('[::1]:8788')).toBe('[::1]');
    expect(hostnameOf('Example.COM:80')).toBe('example.com');
  });
});
