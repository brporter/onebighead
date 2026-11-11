import { beforeEach, expect, it, vi } from 'vitest';
import { api } from '../../src/api/client';
import { authApi } from '../../src/api/auth';
import { createMockCurrentUser } from '../testUtils';

vi.mock('../../src/api/client', () => ({ api: { get: vi.fn(), post: vi.fn() } }));
beforeEach(() => vi.resetAllMocks());

it('forwards cancellation, returns anonymous sessions for 401 and propagates other read failures', async () => {
  const user = createMockCurrentUser();
  const options = { signal: new AbortController().signal };
  vi.mocked(api.get).mockResolvedValueOnce(user).mockRejectedValueOnce({ status: 401 }).mockRejectedValueOnce(new Error('Offline'));
  await expect(authApi.getCurrentUser(options)).resolves.toEqual(user);
  expect(api.get).toHaveBeenCalledWith('/auth/me', options);
  await expect(authApi.getCurrentUser()).resolves.toBeNull();
  await expect(authApi.getCurrentUser()).rejects.toThrow('Offline');
});

it('keeps login and session commands behind the shared HTTP client', async () => {
  await authApi.logout();
  expect(api.post).toHaveBeenLastCalledWith('/auth/logout', undefined, { credentials: 'include' });
  expect(authApi.getLoginUrl('google')).toBe('/api/auth/login/google');
  await authApi.completeWelcome({ workspaceName: 'My Collection' });
  expect(api.post).toHaveBeenLastCalledWith('/auth/complete-welcome', { workspaceName: 'My Collection' });
  await authApi.acceptTerms();
  expect(api.post).toHaveBeenLastCalledWith('/auth/accept-terms', {});
});
