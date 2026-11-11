/**
 * Auth API
 */
import { api, type RequestOptions } from './client';
import type { CurrentUser, SetupCollectionRequest } from '../utils/types';

export interface CompleteWelcomeRequest {
  workspaceName?: string;
  collection?: SetupCollectionRequest;
}

export interface CompleteWelcomeResponse {
  workspaceId: number;
  workspaceName: string;
  hasCompletedWelcome: boolean;
  collectionId: number | null;
  collectionName: string | null;
}

export interface AcceptTermsResponse {
  hasAcceptedTerms: boolean;
  acceptedTermsAt: string;
}

export const authApi = {
  getCurrentUser(options?: RequestOptions): Promise<CurrentUser | null> {
    return api.get<CurrentUser>('/auth/me', options).catch((error) => {
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

  completeWelcome(request: CompleteWelcomeRequest): Promise<CompleteWelcomeResponse> {
    return api.post<CompleteWelcomeResponse>('/auth/complete-welcome', request);
  },

  acceptTerms(): Promise<AcceptTermsResponse> {
    return api.post<AcceptTermsResponse>('/auth/accept-terms', {});
  },
};
