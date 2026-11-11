/**
 * Admin API
 */
import { api, type RequestOptions } from './client';
import type { WorkspaceSummary, UserSummary, ItemTemplate, CreateItemTemplateRequest } from '../utils/types';

export const adminApi = {
  // Workspaces
  getWorkspaces(options?: RequestOptions): Promise<WorkspaceSummary[]> {
    return api.get<WorkspaceSummary[]>('/admin/workspaces', { ...options, credentials: 'include' });
  },

  deleteWorkspace(id: number): Promise<void> {
    return api.delete(`/admin/workspaces/${id}`, { credentials: 'include' });
  },

  // Users
  getUsers(email?: string, options?: RequestOptions): Promise<UserSummary[]> {
    const endpoint = email 
      ? `/admin/users?email=${encodeURIComponent(email)}` 
      : '/admin/users';
    return api.get<UserSummary[]>(endpoint, { ...options, credentials: 'include' });
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
  getSystemTemplates(options?: RequestOptions): Promise<ItemTemplate[]> {
    return api.get<ItemTemplate[]>('/admin/templates', { ...options, credentials: 'include' });
  },

  getSystemTemplate(id: number, options?: RequestOptions): Promise<ItemTemplate> {
    return api.get<ItemTemplate>(`/admin/templates/${id}`, { ...options, credentials: 'include' });
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
