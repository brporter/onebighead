import type { Item } from './types';

export function createEmptyItem(categoryId: number | null, tenantId: number = 1): Item {
  return {
    id: null,
    tenantId,
    categoryId,
    name: '',
    summary: '',
    description: '',
    properties: [],
    images: [],
  };
}

