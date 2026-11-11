import { api, type RequestOptions } from './client';
import type { CurrentUser } from '../utils/types';
import type { InvitationAccess, InvitationPreview } from '../data/invitations/types';

export const invitationsApi = {
  preview: (request: InvitationAccess, options?: RequestOptions) => api.post<InvitationPreview>('/invitations/preview', request, options),
  accept: (request: InvitationAccess) => api.post<CurrentUser>('/invitations/accept', request),
};
