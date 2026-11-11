import { afterEach, expect, it, vi } from 'vitest';
import { api } from '../../src/api/client';
import { accountApi, WorkspaceActionType } from '../../src/api/account';

afterEach(() => vi.restoreAllMocks());

it('reads the current account deletion requirements', async () => {
  const info = { userId: 5, email: 'reader@example.test', workspaceMemberships: [], workspacesRequiringAction: 0, canDeleteImmediately: true };
  const get = vi.spyOn(api, 'get').mockResolvedValue(info);
  await expect(accountApi.getDeletionInfo()).resolves.toBe(info);
  expect(get).toHaveBeenCalledExactlyOnceWith('/users/me/deletion-info');
});

it('sends confirmation and workspace decisions in the DELETE request body', async () => {
  const input = { confirmEmail: 'reader@example.test', workspaceActions: [
    { workspaceId: 1, action: WorkspaceActionType.Delete },
    { workspaceId: 2, action: WorkspaceActionType.Transfer, transferToUserId: 8 },
  ] };
  const response = { success: true };
  const request = vi.spyOn(api, 'request').mockResolvedValue(response);
  await expect(accountApi.deleteAccount(input)).resolves.toBe(response);
  expect(request).toHaveBeenCalledExactlyOnceWith('/users/me', { method: 'DELETE', body: JSON.stringify(input) });
});

it('propagates read and deletion failures to the account workflow', async () => {
  const error = new Error('Session expired');
  vi.spyOn(api, 'get').mockRejectedValue(error);
  vi.spyOn(api, 'request').mockRejectedValue(error);
  await expect(accountApi.getDeletionInfo()).rejects.toBe(error);
  await expect(accountApi.deleteAccount({ confirmEmail: 'reader@example.test', workspaceActions: [] })).rejects.toBe(error);
});
