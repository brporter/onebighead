/**
 * Account API
 * Handles user account deletion and related operations
 */
import { api } from './client';
import type { WorkspaceRole } from '../utils/types';

export enum WorkspaceActionType {
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

export interface WorkspaceMembershipDeletionInfo {
  workspaceId: number;
  workspaceName: string;
  role: WorkspaceRole;
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
  workspaceMemberships: WorkspaceMembershipDeletionInfo[];
  workspacesRequiringAction: number;
  canDeleteImmediately: boolean;
}

export interface WorkspaceActionRequest {
  workspaceId: number;
  action: WorkspaceActionType;
  transferToUserId?: number;
}

export interface DeleteAccountRequest {
  confirmEmail: string;
  workspaceActions: WorkspaceActionRequest[];
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
