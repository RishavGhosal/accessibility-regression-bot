# Rate limit and CSRF fixtures

This portable, bounded runner checks whether repeated invalid login attempts are eventually throttled and whether a cookie-authenticated state change requires an anti-forgery defense. The runner itself performs no network requests, uses no live credentials, and does not probe any URL. Its synthetic fixture values are only inputs for a test adapter.

## Adapter contract

Implement an adapter in the target app's test suite and pass it to `runAbuseFixtures`:

```js
import { runAbuseFixtures } from './abuse.mjs';

const adapter = {
  // Seed/reset only an isolated test database, test server, or in-memory app.
  async seed({ login, stateChange }) { /* create fixture user/session/resource */ },

  // Invoke the application's real login path using the synthetic invalid password.
  // Return { status } for HTTP 429, or { status, throttled: true } for an
  // app-specific challenge/lockout signal that is not represented by 429.
  async loginAttempt({ username, password, clientId, attempt }) { /* real app path */ },

  // Invoke a real cookie-authenticated state-changing path. Map csrfProof to
  // the app's token, required non-safelisted header, Origin/Referer validation,
  // or other configured anti-forgery defense. Missing is undefined.
  async changeState({ cookie, csrfProof, resourceId, update }) { /* real app path */ },
};

const result = await runAbuseFixtures(adapter, { attemptCount: 5 });
if (result.failed.length) throw new Error(JSON.stringify(result.failed));
```

The adapter should preserve the target app's normal login throttling, session-cookie handling, anti-forgery middleware, and route behavior. A throttle may be reported as HTTP 429 or as `{ status, throttled: true }` for an app-specific challenge/lockout signal. The runner stops at the first such signal or unexpected response; server errors fail the check. The default budget is five requests, and configurable `attemptCount` is bounded from 2 to 20. A target app with a higher threshold should pass a justified larger budget explicitly. It must not send these fixture values to a production or third-party host.

The cookie is a synthetic contract value. Both state-change requests use the same cookie-authenticated test session; only `csrfProof` differs. The adapter must map the proof to the target app's actual policy, such as an anti-forgery token, a required non-safelisted header, or origin-based validation. ASVS permits an anti-forgery token or another effective defense; do not force token semantics onto an app whose policy uses a different defense. Ensure the absent-proof case omits the defense input under test and the valid-proof case satisfies the configured policy. Reset state between runs using the test framework's normal cleanup.

## Included cases

- Multiple invalid login attempts eventually return 429.
- A cookie-authenticated state change without the app's required anti-forgery proof returns a 4xx response.
- The same state-change path and cookie session with a valid anti-forgery proof returns 2xx.

## Limits

These are narrow behavioral checks, not a general security assessment. They do not establish a suitable production threshold, test distributed rate-limit storage, account enumeration, lockout recovery, anti-forgery token entropy/rotation, SameSite behavior, CORS, or every state-changing route. Every credentialed state-changing path needs review for a suitable CSRF defense; this fixture covers only the adapted path. A passing contract test exercises only the bundled in-memory example adapter; target-app coverage requires a correct adapter that invokes the real middleware and routes and maps the app's actual policy faithfully.

## Bundled contract tests

Run from the repository root:

```sh
npm test -- skills/app-safety/fixtures/abuse/abuse.runner.test.mjs
```

The in-memory tests include positive and negative controls and never contact a server.
