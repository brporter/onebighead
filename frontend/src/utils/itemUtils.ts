import type { Item } from './types';

export function createEmptyItem(categoryId: number | null, collectionId: number, tenantId: number): Item {
  return {
    id: null,
    tenantId,
    collectionId,
    categoryId,
    name: '',
    summary: '',
    description: '',
    properties: [],
    images: [],
  };
}

