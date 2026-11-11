/**
 * API module for workspace user management.
 */

import { api, type RequestOptions } from './client';
import type { WorkspaceUser, InviteUserRequest, UpdateUserRoleRequest, WorkspaceRole } from '../utils/types';
import type { CreatedInvitation, WorkspaceInvitation } from '../data/invitations/types';

export const usersApi = {
  /**
   * Get all users in the current workspace.
   */
  getUsers(options?: RequestOptions): Promise<WorkspaceUser[]> {
    return api.get<WorkspaceUser[]>('/users', options);
  },

  /**
   * Invite a new user to the workspace by email.
   */
  inviteUser(request: InviteUserRequest): Promise<CreatedInvitation> {
    return api.post<CreatedInvitation>('/users', request);
  },

  getInvitations(options?: RequestOptions): Promise<WorkspaceInvitation[]> {
    return api.get<WorkspaceInvitation[]>('/invitations', options);
  },

  cancelInvitation(id: string): Promise<void> {
    return api.delete<void>(`/invitations/${encodeURIComponent(id)}`);
  },

  /**
   * Update a user's role.
   */
  updateUserRole(userId: number, role: WorkspaceRole): Promise<void> {
    const request: UpdateUserRoleRequest = { role };
    return api.put<void>(`/users/${userId}/role`, request);
  },

  /**
   * Remove a user from the workspace.
   */
  removeUser(userId: number): Promise<void> {
    return api.delete<void>(`/users/${userId}`);
  },
};

export default usersApi;
