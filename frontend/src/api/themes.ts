/**
 * Themes API
 */
import { api } from './client';
import type { CollectionTheme } from '../types';

export const themesApi = {
  /**
   * Get all available collection themes.
   */
  getAll(): Promise<CollectionTheme[]> {
    return api.get<CollectionTheme[]>('/themes');
  },

  /**
   * Get a specific theme by ID.
   */
  getById(id: number): Promise<CollectionTheme> {
    return api.get<CollectionTheme>(`/themes/${id}`);
  },
};
