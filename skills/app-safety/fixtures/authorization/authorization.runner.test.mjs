import { describe, expect, it } from 'vitest';
import { runAuthorizationFixtures } from './authorization.mjs';

const records = [
  { id: 'record-alice-private', ownerId: 'user-alice', tenantId: 'tenant-north', minimumRole: 'member' },
  { id: 'record-bob-private', ownerId: 'user-bob', tenantId: 'tenant-north', minimumRole: 'member' },
  { id: 'record-north-admin', ownerId: 'user-alice', tenantId: 'tenant-north', minimumRole: 'admin' },
  { id: 'record-bob-admin', ownerId: 'user-bob', tenantId: 'tenant-north', minimumRole: 'admin' },
  { id: 'record-south-private', ownerId: 'user-cara', tenantId: 'tenant-south', minimumRole: 'member' },
];

const roles = { member: 1, admin: 2 };
function makeInMemoryAdapter({ enforceRole = true } = {}) {
  const stored = new Map();
  return {
    async seed(fixtures) {
      for (const record of fixtures.records) stored.set(record.id, record);
    },
    async readRecord({ principal, recordId }) {
      const record = stored.get(recordId);
      if (!principal) return { status: 401 };
      if (!record || record.tenantId !== principal.tenantId) return { status: 404 };
      if (record.ownerId !== principal.id || (enforceRole && roles[principal.role] < roles[record.minimumRole])) {
        return { status: 403 };
      }
      return { status: 200, body: record };
    },
  };
}

describe('authorization fixture runner with an in-memory example adapter', () => {
  it('passes its expected allow and deny scenarios', async () => {
    const result = await runAuthorizationFixtures(makeInMemoryAdapter());
    expect(result.failed).toEqual([]);
    expect(result.passed).toHaveLength(8);
  });

  it('detects when a member can read an admin-only record they own', async () => {
    const result = await runAuthorizationFixtures(makeInMemoryAdapter({ enforceRole: false }));
    expect(result.failed.map(({ id }) => id)).toContain('owner-lower-role-admin-record-denied');
  });

  it('detects when another same-tenant user can read a private record', async () => {
    const adapter = makeInMemoryAdapter();
    const original = adapter.readRecord;
    adapter.readRecord = async (request) => {
      if (request.recordId === 'record-alice-private' && request.principal?.id === 'user-bob') {
        return { status: 200, body: records[0] };
      }
      return original(request);
    };
    const result = await runAuthorizationFixtures(adapter);
    expect(result.failed.map(({ id }) => id)).toContain('other-user-private-record-denied');
  });
});
