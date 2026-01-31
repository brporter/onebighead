/**
 * API module for tenant user management.
 */

import { api } from './client';
import type { TenantUser, InviteUserRequest, UpdateUserRoleRequest, TenantRole } from '../utils/types';

export const usersApi = {
  /**
   * Get all users in the current tenant.
   */
  getUsers(): Promise<TenantUser[]> {
    return api.get<TenantUser[]>('/users');
  },

  /**
   * Invite a new user to the tenant by email.
   */
  inviteUser(request: InviteUserRequest): Promise<TenantUser> {
    return api.post<TenantUser>('/users', request);
  },

  /**
   * Update a user's role.
   */
  updateUserRole(userId: number, role: TenantRole): Promise<void> {
    const request: UpdateUserRoleRequest = { role };
    return api.put<void>(`/users/${userId}/role`, request);
  },

  /**
   * Remove a user from the tenant.
   */
  removeUser(userId: number): Promise<void> {
    return api.delete<void>(`/users/${userId}`);
  },
};

export default usersApi;
