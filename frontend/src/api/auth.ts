/**
 * Auth API
 */
import { api } from './client';
import type { CurrentUser } from '../types';

export const authApi = {
  getCurrentUser(): Promise<CurrentUser | null> {
    return api.get<CurrentUser>('/auth/me').catch((error) => {
      if (error.status === 401) {
        return null;
      }
      throw error;
    });
  },

  logout(): Promise<void> {
    return api.post('/auth/logout', undefined, { credentials: 'include' });
  },

  getLoginUrl(provider: string): string {
    return `/api/auth/login/${provider}`;
  },
};
