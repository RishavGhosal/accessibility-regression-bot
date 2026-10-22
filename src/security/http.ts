import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { IncomingHttpHeaders, IncomingMessage } from 'node:http';
import type { SecurityCheck, SecurityFinding } from './types.js';

const REQUEST_TIMEOUT_MS = 5_000;
const SAFE_ERROR = 'HTTP security check failed or the URL is invalid.';

function isLoopback(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '::1' || host === '0:0:0:0:0:0:0:1' || host.startsWith('127.');
}

function headerValue(headers: IncomingHttpHeaders, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  if (Array.isArray(value)) return value.join(', ');
  return typeof value === 'string' ? value : undefined;
}

function cookies(headers: IncomingHttpHeaders): string[] {
  const value = headers['set-cookie'];
  return Array.isArray(value) ? value : value ? [value] : [];
}

function finding(id: string, severity: SecurityFinding['severity'], title: string, guidance: string, location: string): SecurityFinding {
  return { id, category: 'http', severity, title, guidance, location: { url: location } };
}

export function inspectHttpHeaders(headers: IncomingHttpHeaders, url: URL, location: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const https = url.protocol === 'https:';
  const loopback = isLoopback(url.hostname);
  if (https && !loopback && !headerValue(headers, 'strict-transport-security')) {
    findings.push(finding('http.hsts.missing', 'medium', 'HSTS header is missing', 'Review whether this HTTPS site should enforce HTTPS with Strict-Transport-Security.', location));
  }
  if (!headerValue(headers, 'content-security-policy')) {
    findings.push(finding('http.csp.missing', 'review', 'Content Security Policy needs review', 'Review whether a Content-Security-Policy is appropriate and whether its directives fit this site.', location));
  }
  if (!headerValue(headers, 'x-content-type-options')) {
    findings.push(finding('http.content-type-options.missing', 'review', 'X-Content-Type-Options needs review', 'Review whether this response should set X-Content-Type-Options: nosniff.', location));
  }

  for (const cookie of cookies(headers)) {
    const parts = cookie.split(';');
    const name = parts[0]?.split('=', 1)[0]?.trim();
    const safeId = name && /^[A-Za-z0-9_-]{1,40}$/.test(name) ? name : 'cookie';
    const attributes = new Set(parts.slice(1).map(part => part.trim().split('=', 1)[0]?.toLowerCase()));
    const sameSite = parts.slice(1).map(part => part.trim()).find(part => /^samesite=/i.test(part))?.split('=', 2)[1]?.toLowerCase();
    if (!attributes.has('secure') && (https || !loopback)) {
      findings.push(finding('http.cookie.secure.missing', 'medium', 'Cookie Secure flag needs review', `Review the Secure flag for cookie ${safeId}.`, location));
    }
    if (!attributes.has('httponly')) {
      findings.push(finding('http.cookie.httponly.missing', 'review', 'Cookie HttpOnly flag needs review', `Review whether cookie ${safeId} should be HttpOnly.`, location));
    }
    if (!sameSite || !['strict', 'lax', 'none'].includes(sameSite)) {
      findings.push(finding('http.cookie.samesite.missing', 'review', 'Cookie SameSite attribute needs review', `Review the SameSite attribute for cookie ${safeId}.`, location));
    } else if (sameSite === 'none' && !attributes.has('secure')) {
      findings.push(finding('http.cookie.samesite.none', 'medium', 'SameSite=None cookie lacks Secure', `Review cookie ${safeId}: SameSite=None normally requires Secure.`, location));
    }
  }

  const allowOrigin = headerValue(headers, 'access-control-allow-origin')?.trim();
  const allowCredentials = headerValue(headers, 'access-control-allow-credentials')?.trim().toLowerCase() === 'true';
  if (allowOrigin === '*' && allowCredentials) {
    findings.push(finding('http.cors.wildcard-credentials', 'high', 'CORS wildcard origin is paired with credentials', 'Review the CORS policy. Wildcard origins and credentialed access should not be combined.', location));
  } else if (allowOrigin === '*') {
    findings.push(finding('http.cors.wildcard', 'review', 'CORS allows every origin', 'Review whether every web origin needs access to this response.', location));
  } else if (allowOrigin?.toLowerCase() === 'null') {
    findings.push(finding('http.cors.null-origin', 'review', 'CORS allows the null origin', 'Review whether responses should be accessible from opaque origins.', location));
  }
  return findings;
}

function requestHeaders(url: URL): Promise<IncomingMessage> {
  return new Promise((resolve, reject) => {
    const requester = url.protocol === 'https:' ? httpsRequest : httpRequest;
    const req = requester(url, { method: 'GET', headers: { accept: '*/*', 'user-agent': 'security-header-check/1.0' }, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) }, resolve);
    req.on('error', reject);
    req.end();
  });
}

export async function runHttpCheck(input: string): Promise<SecurityCheck> {
  let url: URL;
  try {
    url = new URL(input);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('invalid URL');
  } catch {
    return { name: 'http', status: 'incomplete', findings: [], error: SAFE_ERROR };
  }
  const location = `${url.origin}${url.pathname}`;
  try {
    const response = await requestHeaders(url);
    response.resume();
    return { name: 'http', status: 'complete', findings: inspectHttpHeaders(response.headers, url, location) };
  } catch {
    return { name: 'http', status: 'incomplete', findings: [], error: SAFE_ERROR };
  }
}
