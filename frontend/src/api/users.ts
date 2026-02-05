/**
 * API module for workspace user management.
 */

import { api } from './client';
import type { WorkspaceUser, InviteUserRequest, UpdateUserRoleRequest, WorkspaceRole } from '../utils/types';

export const usersApi = {
  /**
   * Get all users in the current workspace.
   */
  getUsers(): Promise<WorkspaceUser[]> {
    return api.get<WorkspaceUser[]>('/users');
  },

  /**
   * Invite a new user to the workspace by email.
   */
  inviteUser(request: InviteUserRequest): Promise<WorkspaceUser> {
    return api.post<WorkspaceUser>('/users', request);
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
