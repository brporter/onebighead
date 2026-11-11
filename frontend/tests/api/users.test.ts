import { expect, it, vi } from 'vitest';
import { api } from '../../src/api/client';
import { usersApi } from '../../src/api/users';
import { WorkspaceRole } from '../../src/utils/types';
vi.mock('../../src/api/client', () => ({ api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() } }));
it('forwards cancellable team reads and typed membership commands', async () => {
  const options = { signal: new AbortController().signal };
  await usersApi.getUsers(options);
  expect(api.get).toHaveBeenLastCalledWith('/users', options);
  await usersApi.getUsers();
  expect(api.get).toHaveBeenLastCalledWith('/users', undefined);
  const request = { email: 'member@example.com', role: WorkspaceRole.Normal };
  await usersApi.inviteUser(request);
  expect(api.post).toHaveBeenLastCalledWith('/users', request);
  await usersApi.updateUserRole(2, WorkspaceRole.WorkspaceAdmin);
  expect(api.put).toHaveBeenLastCalledWith('/users/2/role', { role: WorkspaceRole.WorkspaceAdmin });
  await usersApi.removeUser(3);
  expect(api.delete).toHaveBeenLastCalledWith('/users/3');
});
