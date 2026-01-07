import { describe, it, expect } from 'vitest';
import { getCategoryAndDescendantIds } from '../src/categoryUtils';
import type { Category } from '../src/types';

describe('getCategoryAndDescendantIds', () => {
  const categories: Category[] = [
    { tenantId: 1, categoryId: 1, name: 'Root 1', description: 'Root 1 desc', parentCategoryId: null, isSystem: false },
    { tenantId: 1, categoryId: 2, name: 'Child 1-1', description: 'Child 1-1 desc', parentCategoryId: 1, isSystem: false },
    { tenantId: 1, categoryId: 3, name: 'Child 1-2', description: 'Child 1-2 desc', parentCategoryId: 1, isSystem: false },
    { tenantId: 1, categoryId: 4, name: 'Grandchild 1-1-1', description: 'Grandchild desc', parentCategoryId: 2, isSystem: false },
    { tenantId: 1, categoryId: 5, name: 'Root 2', description: 'Root 2 desc', parentCategoryId: null, isSystem: false },
  ];

  it('should return empty set when selectedCategoryId is null', () => {
    const result = getCategoryAndDescendantIds(categories, null);
    expect(result).toEqual(new Set());
  });

  it('should return only the selected category when it has no children', () => {
    const result = getCategoryAndDescendantIds(categories, 5);
    expect(result).toEqual(new Set([5]));
  });

  it('should return selected category and all descendants', () => {
    const result = getCategoryAndDescendantIds(categories, 1);
    expect(result).toEqual(new Set([1, 2, 3, 4]));
  });

  it('should return category and its descendants for mid-level selection', () => {
    const result = getCategoryAndDescendantIds(categories, 2);
    expect(result).toEqual(new Set([2, 4]));
  });

  it('should return only leaf category when selecting a leaf', () => {
    const result = getCategoryAndDescendantIds(categories, 4);
    expect(result).toEqual(new Set([4]));
  });

  it('should handle empty categories array', () => {
    const result = getCategoryAndDescendantIds([], 1);
    expect(result).toEqual(new Set([1]));
  });

  it('should handle category that does not exist', () => {
    const result = getCategoryAndDescendantIds(categories, 999);
    expect(result).toEqual(new Set([999]));
  });

  it('should handle categories with null in stack gracefully', () => {
    // This tests the id == null branch in the while loop
    const categoriesWithNullParent: Category[] = [
      { tenantId: 1, categoryId: 1, name: 'Root', description: 'desc', parentCategoryId: null, isSystem: false },
    ];
    const result = getCategoryAndDescendantIds(categoriesWithNullParent, 1);
    expect(result).toEqual(new Set([1]));
  });
});

