const users = Object.freeze([
  Object.freeze({ id: 'user-alice', tenantId: 'tenant-north', role: 'admin' }),
  Object.freeze({ id: 'user-bob', tenantId: 'tenant-north', role: 'member' }),
  Object.freeze({ id: 'user-cara', tenantId: 'tenant-south', role: 'member' }),
]);

const records = Object.freeze([
  Object.freeze({ id: 'record-alice-private', ownerId: 'user-alice', tenantId: 'tenant-north', minimumRole: 'member', visibility: 'private' }),
  Object.freeze({ id: 'record-bob-private', ownerId: 'user-bob', tenantId: 'tenant-north', minimumRole: 'member', visibility: 'private' }),
  Object.freeze({ id: 'record-north-admin', ownerId: 'user-alice', tenantId: 'tenant-north', minimumRole: 'admin', visibility: 'private' }),
  Object.freeze({ id: 'record-bob-admin', ownerId: 'user-bob', tenantId: 'tenant-north', minimumRole: 'admin', visibility: 'private' }),
  Object.freeze({ id: 'record-south-private', ownerId: 'user-cara', tenantId: 'tenant-south', minimumRole: 'member', visibility: 'private' }),
]);

const scenarios = Object.freeze([
  Object.freeze({ id: 'owner-can-read-own-record', actorId: 'user-alice', recordId: 'record-alice-private', access: 'allow' }),
  Object.freeze({ id: 'member-can-read-own-record', actorId: 'user-bob', recordId: 'record-bob-private', access: 'allow' }),
  Object.freeze({ id: 'admin-can-read-own-admin-record', actorId: 'user-alice', recordId: 'record-north-admin', access: 'allow' }),
  Object.freeze({ id: 'other-user-private-record-denied', actorId: 'user-bob', recordId: 'record-alice-private', access: 'deny' }),
  Object.freeze({ id: 'lower-role-admin-record-denied', actorId: 'user-bob', recordId: 'record-north-admin', access: 'deny' }),
  Object.freeze({ id: 'owner-lower-role-admin-record-denied', actorId: 'user-bob', recordId: 'record-bob-admin', access: 'deny' }),
  Object.freeze({ id: 'cross-tenant-record-denied', actorId: 'user-bob', recordId: 'record-south-private', access: 'deny' }),
  Object.freeze({ id: 'unauthenticated-record-denied', actorId: null, recordId: 'record-alice-private', access: 'deny' }),
]);

export const authorizationFixtures = Object.freeze({ users, records, scenarios });

/**
 * Run deterministic access checks against an adapter for the target app.
 * The adapter must seed these fixtures and invoke a real authorization-protected read path.
 * This checks only the supplied identities, records, and access cases.
 */
export async function runAuthorizationFixtures(adapter) {
  if (!adapter || typeof adapter.seed !== 'function' || typeof adapter.readRecord !== 'function') {
    throw new TypeError('adapter must implement async seed(fixtures) and readRecord({ principal, recordId })');
  }

  await adapter.seed(authorizationFixtures);
  const principals = new Map(users.map((user) => [user.id, user]));
  const passed = [];
  const failed = [];

  for (const scenario of scenarios) {
    let response;
    try {
      response = await adapter.readRecord({
        principal: scenario.actorId === null ? null : principals.get(scenario.actorId),
        recordId: scenario.recordId,
      });
    } catch (error) {
      response = { status: Number.isInteger(error?.status) ? error.status : 500 };
    }

    const status = response?.status;
    const allowed = Number.isInteger(status) && status >= 200 && status < 300;
    const passedCase = scenario.access === 'allow' ? allowed : Number.isInteger(status) && status >= 400 && status < 500;
    const result = Object.freeze({
      id: scenario.id,
      expected: scenario.access,
      actual: allowed ? 'allow' : Number.isInteger(status) && status >= 400 && status < 500 ? 'deny' : 'error',
      status: Number.isInteger(status) ? status : null,
    });
    (passedCase ? passed : failed).push(result);
  }

  return Object.freeze({ passed: Object.freeze(passed), failed: Object.freeze(failed) });
}
