import { describe, it, expect } from 'vitest';
import { createEmptyItem } from '../src/itemUtils';

describe('createEmptyItem', () => {
  it('should create an empty item with default tenantId', () => {
    const result = createEmptyItem(5);

    expect(result).toEqual({
      id: null,
      tenantId: 1,
      categoryId: 5,
      name: '',
      summary: '',
      description: '',
      properties: [],
      images: [],
    });
  });

  it('should create an empty item with custom tenantId', () => {
    const result = createEmptyItem(10, 2);

    expect(result).toEqual({
      id: null,
      tenantId: 2,
      categoryId: 10,
      name: '',
      summary: '',
      description: '',
      properties: [],
      images: [],
    });
  });

  it('should create an empty item with null categoryId', () => {
    const result = createEmptyItem(null);

    expect(result).toEqual({
      id: null,
      tenantId: 1,
      categoryId: null,
      name: '',
      summary: '',
      description: '',
      properties: [],
      images: [],
    });
  });
});

