import { describe, it, expect } from 'vitest';
import categories from '../../src/data/categories';

describe('categories data', () => {
  it('should export an array of categories', () => {
    expect(Array.isArray(categories)).toBe(true);
    expect(categories.length).toBeGreaterThan(0);
  });

  it('should have valid category structure for each entry', () => {
    categories.forEach((category) => {
      expect(category).toHaveProperty('tenantId');
      expect(category).toHaveProperty('categoryId');
      expect(category).toHaveProperty('name');
      expect(category).toHaveProperty('description');
      expect(category).toHaveProperty('parentCategoryId');

      expect(typeof category.tenantId).toBe('number');
      expect(typeof category.categoryId).toBe('number');
      expect(typeof category.name).toBe('string');
      expect(typeof category.description).toBe('string');
      expect(category.parentCategoryId === null || typeof category.parentCategoryId === 'number').toBe(true);
    });
  });

  it('should have unique categoryIds', () => {
    const ids = categories.map((c) => c.categoryId);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it('should have at least one root category (parentCategoryId is null)', () => {
    const rootCategories = categories.filter((c) => c.parentCategoryId === null);
    expect(rootCategories.length).toBeGreaterThan(0);
  });
});

