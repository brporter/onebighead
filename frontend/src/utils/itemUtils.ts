import type { Item } from './types';
import { UserFlag, Visibility } from './types';

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
    visibility: Visibility.Default,
    effectiveIsPublic: true,
    userFlag: UserFlag.None,
  };
}

