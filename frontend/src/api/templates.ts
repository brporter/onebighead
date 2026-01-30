/**
 * Item Templates API
 */
import { api } from './client';
import type { ItemTemplate, CreateItemTemplateRequest, UpdateItemTemplateRequest } from '../utils/types';

export type TemplateFilter = 'system' | 'tenant' | 'shared' | 'personal';

export const templatesApi = {
  getAll(filter?: TemplateFilter): Promise<ItemTemplate[]> {
    const endpoint = filter ? `/itemtemplates?filter=${filter}` : '/itemtemplates';
    return api.get<ItemTemplate[]>(endpoint);
  },

  getById(id: number): Promise<ItemTemplate> {
    return api.get<ItemTemplate>(`/itemtemplates/${id}`);
  },

  getForCollection(collectionId: number): Promise<ItemTemplate[]> {
    return api.get<ItemTemplate[]>(`/collections/${collectionId}/templates`);
  },

  create(request: CreateItemTemplateRequest): Promise<ItemTemplate> {
    return api.post<ItemTemplate>('/itemtemplates', request);
  },

  update(id: number, request: UpdateItemTemplateRequest): Promise<ItemTemplate> {
    return api.put<ItemTemplate>(`/itemtemplates/${id}`, request);
  },

  delete(id: number): Promise<void> {
    return api.delete(`/itemtemplates/${id}`);
  },

  associateWithCollection(collectionId: number, templateId: number): Promise<void> {
    return api.post(`/collections/${collectionId}/templates/${templateId}`);
  },

  disassociateFromCollection(collectionId: number, templateId: number): Promise<void> {
    return api.delete(`/collections/${collectionId}/templates/${templateId}`);
  },
};
