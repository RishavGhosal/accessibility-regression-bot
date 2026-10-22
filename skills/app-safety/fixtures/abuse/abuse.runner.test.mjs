import { describe, expect, it } from 'vitest';
import { runAbuseFixtures } from './abuse.mjs';

function makeInMemoryAdapter({ throttle = true, enforceCsrf = true } = {}) {
  let loginCount = 0;
  const calls = [];
  return {
    calls,
    async seed() {},
    async loginAttempt(request) {
      calls.push({ kind: 'login', request });
      loginCount += 1;
      if (throttle && loginCount >= 3) return { status: 429, body: 'must not escape fixture result' };
      return { status: 401 };
    },
    async changeState(request) {
      calls.push({ kind: 'change', request });
      if (enforceCsrf && request.csrfProof !== 'fixture-valid-csrf-proof') return { status: 403 };
      return { status: 200 };
    },
  };
}

describe('abuse fixture runner contract', () => {
  it('passes throttling and CSRF rejection/allow cases with an in-memory adapter', async () => {
    const adapter = makeInMemoryAdapter();
    const result = await runAbuseFixtures(adapter);
    expect(result.failed).toEqual([]);
    expect(result.passed.map(({ id }) => id)).toEqual([
      'repeated-login-attempts-eventually-throttled',
      'cookie-state-change-without-anti-forgery-proof-rejected',
      'cookie-state-change-with-valid-anti-forgery-proof-allowed',
    ]);
    expect(result).not.toHaveProperty('body');
    expect(adapter.calls.filter(({ kind }) => kind === 'login')).toHaveLength(3);
    const changeCalls = adapter.calls.filter(({ kind }) => kind === 'change');
    expect(changeCalls).toHaveLength(2);
    expect(changeCalls[0].request.cookie).toBe(changeCalls[1].request.cookie);
    expect(changeCalls[0].request.csrfProof).toBeUndefined();
    expect(changeCalls[1].request.csrfProof).toBe('fixture-valid-csrf-proof');
  });

  it('accepts an app-specific throttle signal without requiring HTTP 429', async () => {
    const adapter = makeInMemoryAdapter();
    adapter.loginAttempt = async (request) => {
      adapter.calls.push({ kind: 'login', request });
      return request.attempt >= 2 ? { status: 423, throttled: true } : { status: 401 };
    };
    const result = await runAbuseFixtures(adapter);
    expect(result.failed).toEqual([]);
    expect(result.outcomes[0]).toMatchObject({ actual: 'throttled', requests: 2, status: 423 });
  });

  it('fails when repeated invalid login attempts are never throttled', async () => {
    const result = await runAbuseFixtures(makeInMemoryAdapter({ throttle: false }));
    expect(result.failed.map(({ id }) => id)).toContain('repeated-login-attempts-eventually-throttled');
  });

  it('reports a login server error instead of treating it as an ordinary unthrottled attempt', async () => {
    const adapter = makeInMemoryAdapter();
    adapter.loginAttempt = async () => ({ status: 500 });
    const result = await runAbuseFixtures(adapter);
    expect(result.failed.find(({ id }) => id === 'repeated-login-attempts-eventually-throttled')?.actual).toBe('error');
    expect(result.outcomes[0]?.requests).toBe(1);
  });

  it('fails when the app accepts a cookie-authenticated state change without an anti-forgery proof', async () => {
    const result = await runAbuseFixtures(makeInMemoryAdapter({ enforceCsrf: false }));
    expect(result.failed.map(({ id }) => id)).toContain('cookie-state-change-without-anti-forgery-proof-rejected');
  });

  it('validates the bounded request budget', async () => {
    await expect(runAbuseFixtures(makeInMemoryAdapter(), { attemptCount: 1 })).rejects.toThrow(RangeError);
    await expect(runAbuseFixtures(makeInMemoryAdapter(), { attemptCount: 21 })).rejects.toThrow(RangeError);
  });
});
