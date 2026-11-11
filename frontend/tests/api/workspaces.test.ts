import { expect, it, vi } from 'vitest';
import { api } from '../../src/api/client';
import { workspacesApi } from '../../src/api/workspaces';

vi.mock('../../src/api/client', () => ({ api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() } }));

it('keeps workspace reads and cancellation behind the shared client', async () => {
  const options = { signal: new AbortController().signal };
  await workspacesApi.getAll();
  expect(api.get).toHaveBeenLastCalledWith('/workspaces');
  await workspacesApi.getStats(5, options);
  expect(api.get).toHaveBeenLastCalledWith('/workspaces/5/stats', options);
  await workspacesApi.getRestorableWorkspaces(options);
  expect(api.get).toHaveBeenLastCalledWith('/users/me/restorable-workspaces', options);
  await workspacesApi.checkSlug('my-library');
  expect(api.get).toHaveBeenLastCalledWith('/workspaces/check-slug/my-library');
});

it('sends each workspace mutation to its own endpoint with its domain payload', async () => {
  await workspacesApi.create({ name: 'Library' });
  expect(api.post).toHaveBeenLastCalledWith('/workspaces', { name: 'Library' });
  await workspacesApi.switch(4);
  expect(api.post).toHaveBeenLastCalledWith('/workspaces/4/switch');
  await workspacesApi.leave(4);
  expect(api.delete).toHaveBeenLastCalledWith('/workspaces/4/membership');
  await workspacesApi.update(4, { name: 'New library', slug: 'new-library' });
  expect(api.put).toHaveBeenLastCalledWith('/workspaces/4', { name: 'New library', slug: 'new-library' });
  await workspacesApi.setup({ requestId: 'a1234567-1234-1234-1234-123456789abc', workspaceName: 'Library', themeId: 3 });
  expect(api.post).toHaveBeenLastCalledWith('/workspaces/setup', { requestId: 'a1234567-1234-1234-1234-123456789abc', workspaceName: 'Library', themeId: 3 });
  await workspacesApi.deleteWorkspace(4);
  expect(api.delete).toHaveBeenLastCalledWith('/workspaces/4');
  await workspacesApi.transferAdmin(4, { newAdminUserId: 7 });
  expect(api.post).toHaveBeenLastCalledWith('/workspaces/4/transfer-admin', { newAdminUserId: 7 });
  await workspacesApi.restoreWorkspaces({ workspaceIds: [4, 5] });
  expect(api.post).toHaveBeenLastCalledWith('/workspaces/restore', { workspaceIds: [4, 5] });
  await workspacesApi.restoreWorkspace(4);
  expect(api.post).toHaveBeenLastCalledWith('/workspaces/4/restore');
});
