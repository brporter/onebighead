import { describe, it, expect } from 'vitest';
import { createEmptyItem } from '../src/utils/itemUtils';
import { UserFlag, Visibility } from '../src/utils/types';

describe('createEmptyItem', () => {
  it('should create an empty item with provided values', () => {
    const result = createEmptyItem(5, 10, 1);

    expect(result).toEqual({
      id: null,
      workspaceId: 1,
      collectionId: 10,
      categoryId: 5,
      templateKey: null,
      name: '',
      summary: '',
      description: '',
      properties: [],
      images: [],
      visibility: Visibility.Default,
      effectiveIsPublic: true,
      userFlag: UserFlag.Have,
    });
  });

  it('should create an empty item with different workspaceId', () => {
    const result = createEmptyItem(10, 20, 2);

    expect(result).toEqual({
      id: null,
      workspaceId: 2,
      collectionId: 20,
      categoryId: 10,
      templateKey: null,
      name: '',
      summary: '',
      description: '',
      properties: [],
      images: [],
      visibility: Visibility.Default,
      effectiveIsPublic: true,
      userFlag: UserFlag.Have,
    });
  });

  it('should create an empty item with null categoryId', () => {
    const result = createEmptyItem(null, 15, 1);

    expect(result).toEqual({
      id: null,
      workspaceId: 1,
      collectionId: 15,
      categoryId: null,
      templateKey: null,
      name: '',
      summary: '',
      description: '',
      properties: [],
      images: [],
      visibility: Visibility.Default,
      effectiveIsPublic: true,
      userFlag: UserFlag.Have,
    });
  });
});

