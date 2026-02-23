/**
 * Collections API
 */
import { api } from './client';
import type { Collection, SetupCollectionRequest } from '../utils/types';
import { Visibility } from '../utils/types';

export interface CreateCollectionRequest {
  name: string;
  description?: string;
  heroImageUrl?: string;
  visibility?: Visibility;
}

export interface UpdateCollectionRequest {
  name: string;
  description?: string;
  heroImageUrl?: string;
  visibility?: Visibility;
}

export interface CollectionItemHighlightResponse {
  itemId: number;
  itemName: string;
  viewCount: number;
}

export interface RecentItemResponse {
  itemId: number;
  itemName: string;
  createdAt: string;
}

export interface CollectionStatisticsResponse {
  itemCount: number;
  imageCount: number;
  totalImageSizeBytes: number;
  topViewedItems: CollectionItemHighlightResponse[];
  recentlyAddedItems: RecentItemResponse[];
}

export const collectionsApi = {
  getAll(): Promise<Collection[]> {
    return api.get<Collection[]>('/collections');
  },

  getById(id: number): Promise<Collection> {
    return api.get<Collection>(`/collections/${id}`);
  },

  getBySlug(slug: string): Promise<Collection> {
    return api.get<Collection>(`/collections/slug/${slug}`);
  },

  create(request: CreateCollectionRequest): Promise<Collection> {
    return api.post<Collection>('/collections', {
      name: request.name,
      description: request.description,
      heroImageUrl: request.heroImageUrl,
      visibility: request.visibility ?? Visibility.Private,
    });
  },

  /**
   * Create a new collection with a theme applied.
   * Used by the setup wizard for new users and when creating collections.
   */
  setup(request: SetupCollectionRequest): Promise<Collection> {
    return api.post<Collection>('/collections/setup', request);
  },

  update(id: number, request: UpdateCollectionRequest): Promise<Collection> {
    return api.put<Collection>(`/collections/${id}`, request);
  },

  delete(id: number): Promise<void> {
    return api.delete(`/collections/${id}`);
  },

  getStatistics(id: number): Promise<CollectionStatisticsResponse> {
    return api.get<CollectionStatisticsResponse>(`/collections/${id}/statistics`);
  },
};
