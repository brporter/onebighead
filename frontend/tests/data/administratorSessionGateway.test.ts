import { expect, it, vi } from 'vitest';
import { SessionChanges } from '../../src/data/auth/SessionChanges';
import { createAdministratorSessionGateway, type AdministratorSessionPort } from '../../src/data/admin/createAdministratorSessionGateway';
import { deferred } from '../testUtils/deferred';

const account = { userId: 1, email: 'admin@example.test', workspaceId: 1, workspaceName: 'Library',
  identityProvider: 'Google', isSystemAdministrator: false, createdAt: '2026-01-01' };
function gateway() {
  return { getUsers: vi.fn().mockResolvedValue([account]), getWorkspaces: vi.fn().mockResolvedValue([]),
    deleteUser: vi.fn().mockResolvedValue(undefined), deleteWorkspace: vi.fn().mockResolvedValue(undefined),
    setAdminStatus: vi.fn().mockResolvedValue(account) };
}
const cases: { method: 'deleteUser' | 'deleteWorkspace' | 'setAdminStatus'; invoke: (port: AdministratorSessionPort) => Promise<unknown>; fallback: string; cancelled: string }[] = [
  { method: 'deleteUser', invoke: port => port.deleteUser(1), fallback: 'Unable to delete user', cancelled: 'Account deletion cancelled' },
  { method: 'deleteWorkspace', invoke: port => port.deleteWorkspace(1), fallback: 'Unable to delete workspace', cancelled: 'Workspace deletion cancelled' },
  { method: 'setAdminStatus', invoke: port => port.setAdminStatus(1, false), fallback: 'Unable to update administrator status', cancelled: 'Administrator change cancelled' },
];

it('preserves read adapters and mutation results across the session boundary', async () => {
  const source = gateway();
  const changes = new SessionChanges();
  const refresh = vi.fn().mockResolvedValue(undefined);
  const port = createAdministratorSessionGateway(source, changes, refresh, () => true);
  expect(port.getUsers).toBe(source.getUsers);
  expect(port.getWorkspaces).toBe(source.getWorkspaces);
  expect(await port.setAdminStatus(1, false)).toBe(account);
  expect(source.setAdminStatus).toHaveBeenCalledExactlyOnceWith(1, false);
  expect(refresh).toHaveBeenCalledOnce();
  expect(changes.getSnapshot()).toMatchObject({ kind: 'account', pending: false, recovery: false, error: null });
});

it.each(cases)('cancels $method when an editor keeps its draft', async ({ invoke, method, cancelled }) => {
  const source = gateway();
  const changes = new SessionChanges();
  changes.protect({ dirty: true, pending: false });
  const refresh = vi.fn();
  const port = createAdministratorSessionGateway(source, changes, refresh, () => false);
  await expect(invoke(port)).rejects.toThrow(cancelled);
  expect(source[method]).not.toHaveBeenCalled();
  expect(refresh).not.toHaveBeenCalled();
});

it.each(cases)('normalizes unknown $method failures and reconciles the session', async ({ invoke, method, fallback }) => {
  const source = gateway();
  source[method].mockRejectedValue(null);
  const refresh = vi.fn().mockResolvedValue(undefined);
  const port = createAdministratorSessionGateway(source, new SessionChanges(), refresh, () => true);
  await expect(invoke(port)).rejects.toThrow(fallback);
  expect(refresh).toHaveBeenCalledOnce();
});

it('serializes unrelated administrator writes until the current session is confirmed', async () => {
  const source = gateway();
  const read = deferred<void>();
  const refresh = vi.fn().mockReturnValue(read.promise);
  const port = createAdministratorSessionGateway(source, new SessionChanges(), refresh, () => true);
  const removal = port.deleteUser(1);
  await Promise.resolve();
  await expect(port.deleteWorkspace(2)).rejects.toThrow('Workspace deletion cancelled');
  expect(source.deleteWorkspace).not.toHaveBeenCalled();
  read.resolve();
  await removal;
  expect(source.deleteUser).toHaveBeenCalledExactlyOnceWith(1);
});
