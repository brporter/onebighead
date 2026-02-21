import type { Item } from './types';
import { UserFlag, Visibility } from './types';

export function createEmptyItem(categoryId: number | null, collectionId: number, workspaceId: number, templateKey: string | null = null): Item {
  return {
    id: null,
    workspaceId,
    collectionId,
    categoryId,
    templateKey,
    name: '',
    summary: '',
    description: '',
    properties: [],
    images: [],
    visibility: Visibility.Default,
    effectiveIsPublic: true,
    userFlag: UserFlag.Have,
  };
}

