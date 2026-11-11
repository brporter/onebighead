/**
 * Categories API
 */
import { api, type RequestOptions } from './client';
import type { Category } from '../utils/types';

export interface CreateCategoryRequest {
  collectionId: number;
  name: string;
  description?: string;
  parentCategoryId?: number | null;
  itemTemplateIds?: number[];
}

export interface ReorderCategoriesRequest {
  categories: { categoryId: number; sortOrder: number }[];
}

export interface UpdateCategoryRequest {
  name: string;
  description?: string;
  parentCategoryId?: number | null;
  itemTemplateIds?: number[];
}

export const categoriesApi = {
  getAll(collectionId?: number, options?: RequestOptions): Promise<Category[]> {
    if (!collectionId) return api.get<Category[]>('/categories', options);
    const params = new URLSearchParams({ collectionId: String(collectionId) });
    return api.get<Category[]>(`/categories?${params}`, options);
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

  reorder(request: ReorderCategoriesRequest): Promise<Category[]> {
    return api.put<Category[]>('/categories/reorder', request);
  },

  /**
   * Get templates for a category including inherited templates from parent categories.
   */
  getTemplates(categoryId: number, options?: RequestOptions): Promise<number[]> {
    return api.get<number[]>(`/categories/${categoryId}/templates`, options);
  },
};
