import { expect, it, vi } from 'vitest';
import { adminApi } from '../../src/api/admin';
import { api } from '../../src/api/client';

vi.mock('../../src/api/client', () => ({ api: { get: vi.fn(), put: vi.fn(), post: vi.fn(), delete: vi.fn() } }));

it('forwards cancellation for admin reads, encodes partial email searches and includes credentials', async () => {
  const options = { signal: new AbortController().signal };
  await adminApi.getWorkspaces(options);
  expect(api.get).toHaveBeenLastCalledWith('/admin/workspaces', { ...options, credentials: 'include' });
  await adminApi.getUsers('book+reader@', options);
  expect(api.get).toHaveBeenLastCalledWith('/admin/users?email=book%2Breader%40', { ...options, credentials: 'include' });
  await adminApi.getUsers();
  expect(api.get).toHaveBeenLastCalledWith('/admin/users', { credentials: 'include' });
  await adminApi.getSystemTemplates(options);
  expect(api.get).toHaveBeenLastCalledWith('/admin/templates', { ...options, credentials: 'include' });
  await adminApi.getSystemTemplate(4, options);
  expect(api.get).toHaveBeenLastCalledWith('/admin/templates/4', { ...options, credentials: 'include' });
});

it('sends user, workspace and system-template mutations to their specific endpoints', async () => {
  await adminApi.deleteWorkspace(1);
  expect(api.delete).toHaveBeenLastCalledWith('/admin/workspaces/1', { credentials: 'include' });
  await adminApi.deleteUser(2);
  expect(api.delete).toHaveBeenLastCalledWith('/admin/users/2', { credentials: 'include' });
  await adminApi.setAdminStatus(2, true);
  expect(api.put).toHaveBeenLastCalledWith('/admin/users/2/admin', { isSystemAdministrator: true }, { credentials: 'include' });
  const request = { name: 'Books', description: '', properties: [] };
  await adminApi.createSystemTemplate(request);
  expect(api.post).toHaveBeenLastCalledWith('/admin/templates', request, { credentials: 'include' });
  await adminApi.updateSystemTemplate(3, request);
  expect(api.put).toHaveBeenLastCalledWith('/admin/templates/3', request, { credentials: 'include' });
  await adminApi.deleteSystemTemplate(3);
  expect(api.delete).toHaveBeenLastCalledWith('/admin/templates/3', { credentials: 'include' });
});
