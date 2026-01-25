/**
 * Items API
 */
import { api } from './client';
import type { Item } from '../types';

export interface GetItemsOptions {
  categoryId?: number;
  includeDescendants?: boolean;
  etag?: string;
}

export interface GetItemsResult {
  items: Item[];
  etag: string | null;
  notModified: boolean;
}

export const itemsApi = {
  async getAll(options: GetItemsOptions = {}): Promise<GetItemsResult> {
    const params = new URLSearchParams();
    if (options.categoryId !== undefined) {
      params.set('categoryId', options.categoryId.toString());
    }
    if (options.includeDescendants) {
      params.set('includeDescendants', 'true');
    }

    const queryString = params.toString();
    const endpoint = queryString ? `/items?${queryString}` : '/items';

    const headers: HeadersInit = {};
    if (options.etag) {
      headers['If-None-Match'] = options.etag;
    }

    const response = await fetch(`/api${endpoint}`, { headers });
    
    if (response.status === 304) {
      return { items: [], etag: null, notModified: true };
    }

    if (!response.ok) {
      throw new Error(`Failed to fetch items: ${response.statusText}`);
    }

    const items: Item[] = await response.json();
    const etag = response.headers.get('ETag');

    return { items, etag, notModified: false };
  },

  getById(id: number): Promise<Item> {
    return api.get<Item>(`/items/${id}`);
  },

  create(item: Item): Promise<Item> {
    return api.post<Item>('/items', item);
  },

  update(id: number, item: Item): Promise<Item> {
    return api.put<Item>(`/items/${id}`, item);
  },

  delete(id: number): Promise<void> {
    return api.delete(`/items/${id}`);
  },
};
