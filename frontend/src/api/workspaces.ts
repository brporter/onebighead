/**
 * Workspaces API
 */
import { api } from './client';
import type { WorkspaceMembership } from '../utils/types';

export interface CreateWorkspaceRequest {
  name: string;
}

export interface CreateWorkspaceResponse {
  workspaceId: number;
  workspaceName: string;
  workspaceRole: string;
  hasCompletedWelcome: boolean;
}

export interface SwitchWorkspaceResponse {
  success: boolean;
  workspaceId: number;
  workspaceName: string;
}

export interface LeaveWorkspaceResponse {
  success: boolean;
}

export interface UpdateWorkspaceRequest {
  name: string;
}

export interface UpdateWorkspaceResponse {
  workspaceId: number;
  workspaceName: string;
}

export interface SetupWorkspaceRequest {
  workspaceName: string;
  collectionName?: string;
  collectionDescription?: string;
  themeId?: number;
}

export interface SetupWorkspaceResponse {
  workspaceId: number;
  workspaceName: string;
  workspaceRole: string;
  collectionId: number;
  collectionName: string;
}

export interface WorkspaceStats {
  workspaceId: number;
  workspaceName: string;
  collectionCount: number;
  categoryCount: number;
  itemCount: number;
  imageCount: number;
  userCount: number;
  adminCount: number;
}

export interface WorkspaceDeletionResponse {
  success: boolean;
  newActiveWorkspaceId?: number;
  userSoftDeleted?: boolean;
}

export interface TransferAdminRequest {
  newAdminUserId: number;
}

export interface TransferAdminResponse {
  success: boolean;
  error?: string;
}

export interface RestorableWorkspaceStats {
  collectionCount: number;
  itemCount: number;
  categoryCount: number;
  imageCount: number;
}

export interface RestorableWorkspace {
  workspaceId: number;
  name: string;
  deletedAt: string;
  daysRemaining: number;
  stats: RestorableWorkspaceStats;
}

export interface RestoreWorkspacesRequest {
  workspaceIds: number[];
}

export interface RestoreWorkspacesResponse {
  restoredWorkspaceIds: number[];
  activeWorkspaceId: number;
}

export interface RestoreWorkspaceResponse {
  workspaceId: number;
  name: string;
}

export const workspacesApi = {
  /**
   * Get all workspace memberships for the current user
   */
  getAll(): Promise<WorkspaceMembership[]> {
    return api.get<WorkspaceMembership[]>('/workspaces');
  },

  /**
   * Create a new workspace (current user becomes admin)
   */
  create(request: CreateWorkspaceRequest): Promise<CreateWorkspaceResponse> {
    return api.post<CreateWorkspaceResponse>('/workspaces', request);
  },

  /**
   * Switch to a different workspace
   */
  switch(workspaceId: number): Promise<SwitchWorkspaceResponse> {
    return api.post<SwitchWorkspaceResponse>(`/workspaces/${workspaceId}/switch`);
  },

  /**
   * Leave a workspace (remove membership)
   */
  leave(workspaceId: number): Promise<LeaveWorkspaceResponse> {
    return api.delete<LeaveWorkspaceResponse>(`/workspaces/${workspaceId}/membership`);
  },

  /**
   * Update a workspace's details (requires admin)
   */
  update(workspaceId: number, request: UpdateWorkspaceRequest): Promise<UpdateWorkspaceResponse> {
    return api.put<UpdateWorkspaceResponse>(`/workspaces/${workspaceId}`, request);
  },

  /**
   * Set up a new workspace with an initial collection.
   * This is the recommended way to create a new workspace.
   */
  setup(request: SetupWorkspaceRequest): Promise<SetupWorkspaceResponse> {
    return api.post<SetupWorkspaceResponse>('/workspaces/setup', request);
  },

  /**
   * Get deletion statistics for a workspace (requires admin)
   */
  getStats(workspaceId: number): Promise<WorkspaceStats> {
    return api.get<WorkspaceStats>(`/workspaces/${workspaceId}/stats`);
  },

  /**
   * Soft-delete a workspace (requires admin)
   */
  deleteWorkspace(workspaceId: number): Promise<WorkspaceDeletionResponse> {
    return api.delete<WorkspaceDeletionResponse>(`/workspaces/${workspaceId}`);
  },

  /**
   * Transfer admin role to another user (requires admin)
   */
  transferAdmin(workspaceId: number, request: TransferAdminRequest): Promise<TransferAdminResponse> {
    return api.post<TransferAdminResponse>(`/workspaces/${workspaceId}/transfer-admin`, request);
  },

  /**
   * Get soft-deleted workspaces the current user can restore
   */
  getRestorableWorkspaces(): Promise<RestorableWorkspace[]> {
    return api.get<RestorableWorkspace[]>('/users/me/restorable-workspaces');
  },

  /**
   * Restore multiple soft-deleted workspaces
   */
  restoreWorkspaces(request: RestoreWorkspacesRequest): Promise<RestoreWorkspacesResponse> {
    return api.post<RestoreWorkspacesResponse>('/workspaces/restore', request);
  },

  /**
   * Restore a single soft-deleted workspace
   */
  restoreWorkspace(workspaceId: number): Promise<RestoreWorkspaceResponse> {
    return api.post<RestoreWorkspaceResponse>(`/workspaces/${workspaceId}/restore`);
  },
};
