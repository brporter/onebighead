/**
 * Tenants API
 */
import { api } from './client';
import type { TenantMembership } from '../utils/types';

export interface CreateTenantRequest {
  name: string;
}

export interface CreateTenantResponse {
  tenantId: number;
  tenantName: string;
  tenantRole: string;
  hasCompletedWelcome: boolean;
}

export interface SwitchTenantResponse {
  success: boolean;
  tenantId: number;
  tenantName: string;
}

export interface LeaveTenantResponse {
  success: boolean;
}

export interface UpdateTenantRequest {
  name: string;
}

export interface UpdateTenantResponse {
  tenantId: number;
  tenantName: string;
}

export interface SetupTenantRequest {
  tenantName: string;
  collectionName?: string;
  collectionDescription?: string;
  themeId?: number;
}

export interface SetupTenantResponse {
  tenantId: number;
  tenantName: string;
  tenantRole: string;
  collectionId: number;
  collectionName: string;
}

export interface TenantStats {
  tenantId: number;
  tenantName: string;
  collectionCount: number;
  categoryCount: number;
  itemCount: number;
  imageCount: number;
  userCount: number;
  adminCount: number;
}

export interface TenantDeletionResponse {
  success: boolean;
  newActiveTenantId?: number;
  userSoftDeleted?: boolean;
}

export interface TransferAdminRequest {
  newAdminUserId: number;
}

export interface TransferAdminResponse {
  success: boolean;
  error?: string;
}

export interface RestorableTenantStats {
  collectionCount: number;
  itemCount: number;
  categoryCount: number;
  imageCount: number;
}

export interface RestorableTenant {
  tenantId: number;
  name: string;
  deletedAt: string;
  daysRemaining: number;
  stats: RestorableTenantStats;
}

export interface RestoreTenantsRequest {
  tenantIds: number[];
}

export interface RestoreTenantsResponse {
  restoredTenantIds: number[];
  activeTenantId: number;
}

export interface RestoreTenantResponse {
  tenantId: number;
  name: string;
}

export const tenantsApi = {
  /**
   * Get all tenant memberships for the current user
   */
  getAll(): Promise<TenantMembership[]> {
    return api.get<TenantMembership[]>('/tenants');
  },

  /**
   * Create a new tenant (current user becomes TenantAdmin)
   */
  create(request: CreateTenantRequest): Promise<CreateTenantResponse> {
    return api.post<CreateTenantResponse>('/tenants', request);
  },

  /**
   * Switch to a different tenant
   */
  switch(tenantId: number): Promise<SwitchTenantResponse> {
    return api.post<SwitchTenantResponse>(`/tenants/${tenantId}/switch`);
  },

  /**
   * Leave a tenant (remove membership)
   */
  leave(tenantId: number): Promise<LeaveTenantResponse> {
    return api.delete<LeaveTenantResponse>(`/tenants/${tenantId}/membership`);
  },

  /**
   * Update a tenant's details (requires TenantAdmin)
   */
  update(tenantId: number, request: UpdateTenantRequest): Promise<UpdateTenantResponse> {
    return api.put<UpdateTenantResponse>(`/tenants/${tenantId}`, request);
  },

  /**
   * Set up a new tenant with an initial collection.
   * This is the recommended way to create a new tenant.
   */
  setup(request: SetupTenantRequest): Promise<SetupTenantResponse> {
    return api.post<SetupTenantResponse>('/tenants/setup', request);
  },

  /**
   * Get deletion statistics for a tenant (requires TenantAdmin)
   */
  getStats(tenantId: number): Promise<TenantStats> {
    return api.get<TenantStats>(`/tenants/${tenantId}/stats`);
  },

  /**
   * Soft-delete a tenant (requires TenantAdmin)
   */
  deleteTenant(tenantId: number): Promise<TenantDeletionResponse> {
    return api.delete<TenantDeletionResponse>(`/tenants/${tenantId}`);
  },

  /**
   * Transfer admin role to another user (requires TenantAdmin)
   */
  transferAdmin(tenantId: number, request: TransferAdminRequest): Promise<TransferAdminResponse> {
    return api.post<TransferAdminResponse>(`/tenants/${tenantId}/transfer-admin`, request);
  },

  /**
   * Get soft-deleted tenants the current user can restore
   */
  getRestorableTenants(): Promise<RestorableTenant[]> {
    return api.get<RestorableTenant[]>('/users/me/restorable-tenants');
  },

  /**
   * Restore multiple soft-deleted tenants
   */
  restoreTenants(request: RestoreTenantsRequest): Promise<RestoreTenantsResponse> {
    return api.post<RestoreTenantsResponse>('/tenants/restore', request);
  },

  /**
   * Restore a single soft-deleted tenant
   */
  restoreTenant(tenantId: number): Promise<RestoreTenantResponse> {
    return api.post<RestoreTenantResponse>(`/tenants/${tenantId}/restore`);
  },
};
