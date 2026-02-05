/**
 * Account API
 * Handles user account deletion and related operations
 */
import { api } from './client';
import type { TenantRole } from '../utils/types';

export enum TenantActionType {
  Delete = 'Delete',
  Transfer = 'Transfer'
}

export enum DeletionBlockerReason {
  None = 'None',
  SoleUser = 'SoleUser',
  SoleAdmin = 'SoleAdmin'
}

export interface UserBasicInfo {
  userId: number;
  email: string;
}

export interface TenantMembershipDeletionInfo {
  tenantId: number;
  tenantName: string;
  role: TenantRole;
  isOnlyUser: boolean;
  isOnlyAdmin: boolean;
  userCount: number;
  canLeave: boolean;
  blockerReason: DeletionBlockerReason;
  otherUsers: UserBasicInfo[];
}

export interface UserDeletionInfo {
  userId: number;
  email: string;
  tenantMemberships: TenantMembershipDeletionInfo[];
  tenantsRequiringAction: number;
  canDeleteImmediately: boolean;
}

export interface TenantActionRequest {
  tenantId: number;
  action: TenantActionType;
  transferToUserId?: number;
}

export interface DeleteAccountRequest {
  confirmEmail: string;
  tenantActions: TenantActionRequest[];
}

export interface DeleteAccountResponse {
  success: boolean;
  error?: string;
}

export const accountApi = {
  /**
   * Get deletion info for the current user's account
   */
  getDeletionInfo(): Promise<UserDeletionInfo> {
    return api.get<UserDeletionInfo>('/users/me/deletion-info');
  },

  /**
   * Delete the current user's account
   */
  deleteAccount(request: DeleteAccountRequest): Promise<DeleteAccountResponse> {
    return api.request<DeleteAccountResponse>('/users/me', {
      method: 'DELETE',
      body: JSON.stringify(request),
    });
  },
};
