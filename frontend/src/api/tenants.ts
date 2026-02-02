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
};
