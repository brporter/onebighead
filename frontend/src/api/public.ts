import { api, type RequestOptions } from './client';

export interface PublicWorkspace {
  name: string;
  slug: string;
}

export interface PublicCollection {
  id: number;
  name: string;
  description: string;
  heroImageUrl: string | null;
  slug: string;
}

export interface PublicCategory {
  id: number;
  name: string;
  parentCategoryId: number | null;
  isSystem: boolean;
  itemTemplateIds: number[];
}

export interface PublicCollectionDetail {
  collection: PublicCollection;
  categories: PublicCategory[];
}

export interface PublicItemSummary {
  id: number;
  name: string;
  summary: string;
  primaryImageUrl: string | null;
  categoryId: number | null;
}

export interface PublicItemProperty {
  category: string;
  name: string;
  value: string;
}

export interface PublicItemImage {
  url: string;
  alt: string | null;
}

export interface PublicItem {
  id: number;
  name: string;
  summary: string;
  description: string;
  properties: PublicItemProperty[];
  images: PublicItemImage[];
  categoryId: number | null;
  categoryName: string | null;
  templateKey: string | null;
}

export const publicApi = {
  getWorkspace(slug: string, options?: RequestOptions): Promise<PublicWorkspace> {
    return api.get<PublicWorkspace>(`/public/${slug}`, options);
  },

  getCollections(slug: string, options?: RequestOptions): Promise<PublicCollection[]> {
    return api.get<PublicCollection[]>(`/public/${slug}/collections`, options);
  },

  getCollection(slug: string, collectionId: number, options?: RequestOptions): Promise<PublicCollectionDetail> {
    return api.get<PublicCollectionDetail>(`/public/${slug}/collections/${collectionId}`, options);
  },

  getItems(slug: string, collectionId: number, categoryId?: number, options?: RequestOptions): Promise<PublicItemSummary[]> {
    const params = categoryId ? `?categoryId=${categoryId}` : '';
    return api.get<PublicItemSummary[]>(`/public/${slug}/collections/${collectionId}/items${params}`, options);
  },

  getItem(slug: string, itemId: number, options?: RequestOptions): Promise<PublicItem> {
    return api.get<PublicItem>(`/public/${slug}/items/${itemId}`, options);
  },
};
