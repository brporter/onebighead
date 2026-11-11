import { expect, it, vi } from 'vitest';
import { createAccountDeletionGateway } from '../../src/data/account/createAccountDeletionGateway';
import { SessionChanges } from '../../src/data/auth/SessionChanges';
import type { DeleteAccountResponse } from '../../src/api/account';
import { deferred } from '../testUtils/deferred';

const request = { confirmEmail: 'owner@example.test', workspaceActions: [] };
function source() { return { getDeletionInfo: vi.fn(), deleteAccount: vi.fn().mockResolvedValue({ success: true }) }; }

it('preserves the preview adapter and ends a confirmed deletion without a second request', async () => {
  const api = source();
  const changes = new SessionChanges();
  const refresh = vi.fn();
  const gateway = createAccountDeletionGateway(api, changes, refresh, () => true);
  expect(gateway.getDeletionInfo).toBe(api.getDeletionInfo);
  expect(await gateway.deleteAccount(request)).toEqual({ success: true });
  expect(api.deleteAccount).toHaveBeenCalledExactlyOnceWith(request);
  expect(refresh).not.toHaveBeenCalled();
  expect(changes.getSnapshot()).toMatchObject({ kind: 'account-deletion', leaving: true, pending: false });
  await expect(gateway.deleteAccount(request)).rejects.toThrow('Account deletion cancelled');
  expect(api.deleteAccount).toHaveBeenCalledOnce();
});

it.each([undefined, 'Workspace changed'])('requires success and reconciles a rejected result with error %s', async error => {
  const api = source();
  api.deleteAccount.mockResolvedValue({ success: false, error });
  const refresh = vi.fn();
  const changes = new SessionChanges();
  const gateway = createAccountDeletionGateway(api, changes, refresh, () => true);
  await expect(gateway.deleteAccount(request)).rejects.toThrow(error ?? 'Failed to delete account');
  expect(refresh).toHaveBeenCalledOnce();
  expect(changes.getSnapshot().leaving).toBe(false);
});

it('blocks deletion for pending editors and allows a dirty editor to keep its draft', async () => {
  const api = source();
  const changes = new SessionChanges();
  const refresh = vi.fn();
  const confirm = vi.fn().mockReturnValue(false);
  const gateway = createAccountDeletionGateway(api, changes, refresh, confirm);
  const release = changes.protect({ dirty: true, pending: true });
  await expect(gateway.deleteAccount(request)).rejects.toThrow('Wait for the current action');
  expect(confirm).not.toHaveBeenCalled();
  release();
  changes.protect({ dirty: true, pending: false });
  await expect(gateway.deleteAccount(request)).rejects.toThrow('Account deletion cancelled');
  expect(confirm).toHaveBeenCalledOnce();
  expect(api.deleteAccount).not.toHaveBeenCalled();
  expect(refresh).not.toHaveBeenCalled();
});

it('holds a lost response through read failure and retries only the session read', async () => {
  const api = source();
  api.deleteAccount.mockRejectedValue(null);
  const refresh = vi.fn().mockRejectedValueOnce(new Error('Session offline')).mockResolvedValue(undefined);
  const changes = new SessionChanges();
  const gateway = createAccountDeletionGateway(api, changes, refresh, () => true);
  await expect(gateway.deleteAccount(request)).rejects.toThrow('Review workspace choices');
  await expect(gateway.deleteAccount(request)).rejects.toThrow('Review workspace choices');
  expect(changes.getSnapshot().recovery).toBe(true);
  await changes.retryRefresh();
  expect(refresh).toHaveBeenCalledTimes(2);
  expect(api.deleteAccount).toHaveBeenCalledOnce();
  expect(changes.getSnapshot()).toMatchObject({ recovery: false, error: 'Failed to delete account', leaving: false });
});

it('serializes repeated clicks while the deletion request is pending', async () => {
  const api = source();
  const write = deferred<DeleteAccountResponse>();
  api.deleteAccount.mockReturnValue(write.promise);
  const gateway = createAccountDeletionGateway(api, new SessionChanges(), vi.fn(), () => true);
  const first = gateway.deleteAccount(request);
  await expect(gateway.deleteAccount(request)).rejects.toThrow('Account deletion cancelled');
  write.resolve({ success: true });
  await first;
  expect(api.deleteAccount).toHaveBeenCalledOnce();
});
