/**
 * Admin API
 */
import { api } from './client';
import type { TenantSummary, UserSummary, ItemTemplate, CreateItemTemplateRequest } from '../types';

export const adminApi = {
  // Tenants
  getTenants(): Promise<TenantSummary[]> {
    return api.get<TenantSummary[]>('/admin/tenants', { credentials: 'include' });
  },

  deleteTenant(id: number): Promise<void> {
    return api.delete(`/admin/tenants/${id}`, { credentials: 'include' });
  },

  // Users
  getUsers(email?: string): Promise<UserSummary[]> {
    const endpoint = email 
      ? `/admin/users?email=${encodeURIComponent(email)}` 
      : '/admin/users';
    return api.get<UserSummary[]>(endpoint, { credentials: 'include' });
  },

  deleteUser(id: number): Promise<void> {
    return api.delete(`/admin/users/${id}`, { credentials: 'include' });
  },

  setAdminStatus(userId: number, isSystemAdministrator: boolean): Promise<UserSummary> {
    return api.put<UserSummary>(
      `/admin/users/${userId}/admin`,
      { isSystemAdministrator },
      { credentials: 'include' }
    );
  },

  // System Templates
  getSystemTemplates(): Promise<ItemTemplate[]> {
    return api.get<ItemTemplate[]>('/admin/templates', { credentials: 'include' });
  },

  getSystemTemplate(id: number): Promise<ItemTemplate> {
    return api.get<ItemTemplate>(`/admin/templates/${id}`, { credentials: 'include' });
  },

  createSystemTemplate(request: CreateItemTemplateRequest): Promise<ItemTemplate> {
    return api.post<ItemTemplate>('/admin/templates', request, { credentials: 'include' });
  },

  updateSystemTemplate(id: number, request: CreateItemTemplateRequest): Promise<ItemTemplate> {
    return api.put<ItemTemplate>(`/admin/templates/${id}`, request, { credentials: 'include' });
  },

  deleteSystemTemplate(id: number): Promise<void> {
    return api.delete(`/admin/templates/${id}`, { credentials: 'include' });
  },
};
