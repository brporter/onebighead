/**
 * Auth API
 */
import { api } from './client';
import type { CurrentUser } from '../utils/types';

export interface CompleteWelcomeResponse {
  workspaceId: number;
  workspaceName: string;
  hasCompletedWelcome: boolean;
}

export interface AcceptTermsResponse {
  hasAcceptedTerms: boolean;
  acceptedTermsAt: string;
}

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

  completeWelcome(workspaceName?: string): Promise<CompleteWelcomeResponse> {
    return api.post<CompleteWelcomeResponse>('/auth/complete-welcome', { workspaceName });
  },

  acceptTerms(): Promise<AcceptTermsResponse> {
    return api.post<AcceptTermsResponse>('/auth/accept-terms', {});
  },
};
