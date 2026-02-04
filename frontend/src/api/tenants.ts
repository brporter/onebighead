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
}

export interface TransferAdminRequest {
  newAdminUserId: number;
}

export interface TransferAdminResponse {
  success: boolean;
  error?: string;
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
};
