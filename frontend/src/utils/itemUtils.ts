import type { Item } from './types';
import { UserFlag } from './types';

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
    isPublicOverride: null,
    effectiveIsPublic: true,
    userFlag: UserFlag.None,
  };
}

