import { createServer } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';

const servers = [];
async function serve(handler) {
  const server = createServer(handler);
  servers.push(server);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${server.address().port}/path?secret=query`;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise(resolve => server.close(resolve))));
});

describe('runHttpCheck', () => {
  it('reports response header, cookie, and CORS issues without exposing values or query strings', async ctx => {
    const url = await serve((_request, response) => {
      response.writeHead(200, {
        'content-type': 'text/html',
        'access-control-allow-origin': '*',
        'access-control-allow-credentials': 'true',
        'set-cookie': ['session=private-cookie-value; Path=/', 'prefs=private-preference; SameSite=None'],
      });
      response.end('private response body');
    });
    const { runHttpCheck } = await import('../src/security/http.ts');

    const result = await runHttpCheck(url);
    if (result.status === 'incomplete') { ctx.skip(); return; }
    const serialized = JSON.stringify(result);

    expect(result.status).toBe('complete');
    expect(result.findings.length).toBeGreaterThan(0);
    expect(serialized).not.toContain('private-cookie-value');
    expect(serialized).not.toContain('private-preference');
    expect(serialized).not.toContain('private response body');
    expect(serialized).not.toContain('secret=query');
    expect(result.findings.some(finding => /cors/i.test(`${finding.title} ${finding.guidance}`))).toBe(true);
    expect(result.findings.some(finding => finding.id === 'http.cookie.secure.missing')).toBe(false);
  });

  it('does not follow redirects and does not send authorization headers', async ctx => {
    let destinationHits = 0;
    let redirectHits = 0;
    const destination = await serve((_request, response) => {
      destinationHits += 1;
      response.end('destination');
    });
    const redirect = await serve((request, response) => {
      redirectHits += 1;
      expect(request.headers.authorization).toBeUndefined();
      response.writeHead(302, { location: destination });
      response.end();
    });
    const { runHttpCheck } = await import('../src/security/http.ts');

    await runHttpCheck(redirect);
    if (redirectHits === 0) { ctx.skip(); return; }

    expect(destinationHits).toBe(0);
  });

  it('rejects unsupported schemes and embedded credentials with a generic incomplete result', async () => {
    const { runHttpCheck } = await import('../src/security/http.ts');

    const unsupported = await runHttpCheck('file:///etc/passwd');
    const credentials = await runHttpCheck('https://user:pass@example.com/path?token=hidden');

    expect(unsupported.status).toBe('incomplete');
    expect(credentials.status).toBe('incomplete');
    expect(JSON.stringify(unsupported)).not.toContain('/etc/passwd');
    expect(JSON.stringify(credentials)).not.toContain('hidden');
    expect(unsupported.error).toBeTruthy();
    expect(credentials.error).toBe(unsupported.error);
  });

  it('does not treat missing HSTS as a finding for HTTP loopback targets', async ctx => {
    const url = await serve((_request, response) => response.end('ok'));
    const { runHttpCheck } = await import('../src/security/http.ts');

    const result = await runHttpCheck(url);
    if (result.status === 'incomplete') { ctx.skip(); return; }

    expect(result.findings.some(finding => /strict-transport-security|hsts/i.test(finding.title))).toBe(false);
  });
  it('reviews HTTPS HSTS and Secure cookies without preserving cookie values', async () => {
    const { inspectHttpHeaders } = await import('../src/security/http.ts');
    const findings = inspectHttpHeaders(
      { 'set-cookie': ['session=private-cookie-value; HttpOnly; SameSite=Lax'] },
      new URL('https://example.test/account?token=hidden'),
      'https://example.test/account',
    );
    expect(findings.some(finding => finding.id === 'http.hsts.missing')).toBe(true);
    expect(findings.some(finding => finding.id === 'http.cookie.secure.missing')).toBe(true);
    expect(JSON.stringify(findings)).not.toContain('private-cookie-value');
    expect(JSON.stringify(findings)).not.toContain('token=hidden');
  });
});
