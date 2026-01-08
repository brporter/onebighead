import { describe, it, expect } from 'vitest';
import { createEmptyItem } from '../src/itemUtils';

describe('createEmptyItem', () => {
  it('should create an empty item with provided values', () => {
    const result = createEmptyItem(5, 10, 1);

    expect(result).toEqual({
      id: null,
      tenantId: 1,
      collectionId: 10,
      categoryId: 5,
      name: '',
      summary: '',
      description: '',
      properties: [],
      images: [],
    });
  });

  it('should create an empty item with different tenantId', () => {
    const result = createEmptyItem(10, 20, 2);

    expect(result).toEqual({
      id: null,
      tenantId: 2,
      collectionId: 20,
      categoryId: 10,
      name: '',
      summary: '',
      description: '',
      properties: [],
      images: [],
    });
  });

  it('should create an empty item with null categoryId', () => {
    const result = createEmptyItem(null, 15, 1);

    expect(result).toEqual({
      id: null,
      tenantId: 1,
      collectionId: 15,
      categoryId: null,
      name: '',
      summary: '',
      description: '',
      properties: [],
      images: [],
    });
  });
});

