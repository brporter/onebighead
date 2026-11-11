/** Application HTTP composition root. Domain adapters import this singleton. */
import { handleUnauthorized } from '../utils/authErrors';
import { ApiClient } from './transport';

export { ApiClient, ApiError } from './transport';
export type { ApiClientConfig, RequestOptions } from './transport';

// Cleanup must not trigger another auth callback if logout also returns 401.
const authCleanup = new ApiClient({ baseUrl: '/api' });

async function clearAuthAndRedirect(reason: string): Promise<void> {
  console.warn(`${reason} - clearing auth and redirecting to home page`);
  try {
    await authCleanup.post('/auth/logout');
  } catch {
    // Redirect even when the deleted account can no longer log out.
  }
  window.location.href = '/';
}

export const api = new ApiClient({
  baseUrl: '/api',
  onUnauthorized: handleUnauthorized,
  onUserDeleted: () => {
    void clearAuthAndRedirect('User account deleted');
  },
  onNoActiveWorkspaces: () => {
    void clearAuthAndRedirect('User has no active workspaces');
  },
});

export default api;
