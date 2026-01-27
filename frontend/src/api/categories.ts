/**
 * Categories API
 */
import { api } from './client';
import type { Category } from '../types';

export interface CreateCategoryRequest {
  collectionId: number;
  name: string;
  description?: string;
  parentCategoryId?: number | null;
  isPublicOverride?: boolean | null;
  itemTemplateIds?: number[];
}

export interface UpdateCategoryRequest {
  name: string;
  description?: string;
  parentCategoryId?: number | null;
  isPublicOverride?: boolean | null;
  itemTemplateIds?: number[];
}

export const categoriesApi = {
  getAll(collectionId?: number): Promise<Category[]> {
    const endpoint = collectionId 
      ? `/categories?collectionId=${collectionId}` 
      : '/categories';
    return api.get<Category[]>(endpoint);
  },

  getById(id: number): Promise<Category> {
    return api.get<Category>(`/categories/${id}`);
  },

  create(request: CreateCategoryRequest): Promise<Category> {
    return api.post<Category>('/categories', request);
  },

  update(id: number, request: UpdateCategoryRequest): Promise<Category> {
    return api.put<Category>(`/categories/${id}`, request);
  },

  delete(id: number): Promise<void> {
    return api.delete(`/categories/${id}`);
  },

  /**
   * Get templates for a category including inherited templates from parent categories.
   */
  getTemplates(categoryId: number): Promise<number[]> {
    return api.get<number[]>(`/categories/${categoryId}/templates`);
  },
};
