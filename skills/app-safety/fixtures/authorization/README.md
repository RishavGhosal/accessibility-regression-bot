# Authorization fixtures for JavaScript and TypeScript APIs

This portable fixture runner checks a small, deterministic set of role and ownership boundaries against an app adapter. It does not contact external services and contains no credentials.

These scenarios support review of OWASP ASVS 5.0.0 authorization requirements [8.2.1 and 8.2.2](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x17-V8-Authorization.md), with a cross-tenant case relevant to 8.4.1. Passing them does not establish ASVS conformance.

## Included cases

- A user and an admin can read their own records.
- A member is denied another same-tenant user's private record.
- A member is denied an admin-only record, including one the member owns (isolating role enforcement).
- A user is denied a record in another tenant.
- An unauthenticated request is denied.

A denial may be represented by any client error status (400–499), including 401, 403, or 404. Successful access must be 2xx. Server errors, redirects, missing statuses, and unexpected results fail the check.

## Adapter contract

Create an adapter in your app's test suite and pass it to `runAuthorizationFixtures`:

```js
import { runAuthorizationFixtures } from './authorization.mjs';

const adapter = {
  // Create the supplied users and records in your test database or app fixture.
  async seed({ users, records }) { /* map deterministic fixture data into app models */ },

  // Call the app's actual protected read route/service, not a reimplementation of its policy.
  // principal is null for the unauthenticated scenario. Return { status, body? }.
  async readRecord({ principal, recordId }) { /* invoke API handler or HTTP endpoint */ },
};

const result = await runAuthorizationFixtures(adapter);
if (result.failed.length) throw new Error(JSON.stringify(result.failed));
```

For HTTP apps, the adapter can create a test request with the fixture principal's established test session or auth context and return the response status. For service-level tests, call the service method that enforces authorization. Keep the app's normal authorization middleware, tenant scoping, and role checks active. Map the fixture's stable `id`, `tenantId`, and `role` fields to the app's own account fields.

Call `adapter.seed` on an isolated test database or disposable transaction. The adapter should reset or clean up its fixture state using the test framework's normal lifecycle. Do not point it at production data or use real account credentials.

## Limits

A passing run means only that these particular app paths denied or allowed these particular cases under the adapter. It does not prove complete authorization, cover every route or role, test write operations, or replace a broader access-control review. Extend the fixtures for the target app's data model and policy boundaries.

## Running the bundled contract tests

From the repository root, run:

```sh
npm test -- skills/app-safety/fixtures/authorization/authorization.runner.test.mjs
```

The runner contract test uses a local in-memory example adapter to exercise all included cases and confirms it detects same-tenant disclosure and role-check bypasses. It does not test a target app until you provide an app-specific adapter.
