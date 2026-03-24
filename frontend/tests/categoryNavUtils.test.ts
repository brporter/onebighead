import { describe, it, expect } from 'vitest';
import { buildDrillPath, getVisibleCategories, getBreadcrumb, getChildCount } from '../src/utils/categoryNavUtils';
import type { Category } from '../src/utils/types';
import { Visibility } from '../src/utils/types';

function cat(id: number, name: string, parentId: number | null = null): Category {
  return {
    workspaceId: 1, collectionId: 1, categoryId: id, name, description: '',
    parentCategoryId: parentId, isSystem: false, visibility: Visibility.Private,
    effectiveIsPublic: false, itemTemplateIds: [],
  };
}

const categories: Category[] = [
  cat(1, 'Rangefinders'),
  cat(2, '35mm Film', 1),
  cat(3, 'Medium Format', 1),
  cat(4, 'Leica', 2),
  cat(5, 'SLR Cameras'),
  cat(6, 'Nikon', 5),
];

describe('buildDrillPath', () => {
  it('should return empty array for null categoryId', () => {
    expect(buildDrillPath(categories, null)).toEqual([]);
  });

  it('should return single-element path for root category', () => {
    expect(buildDrillPath(categories, 1)).toEqual([1]);
  });

  it('should return full ancestry path for nested category', () => {
    expect(buildDrillPath(categories, 4)).toEqual([1, 2, 4]);
  });

  it('should return path for direct child', () => {
    expect(buildDrillPath(categories, 2)).toEqual([1, 2]);
  });

  it('should return empty array for unknown categoryId', () => {
    expect(buildDrillPath(categories, 999)).toEqual([]);
  });
});

describe('getVisibleCategories', () => {
  it('should return root categories when drillPath is empty', () => {
    const visible = getVisibleCategories(categories, []);
    expect(visible.map(c => c.categoryId)).toEqual([1, 5]);
  });

  it('should return children of drilled category', () => {
    const visible = getVisibleCategories(categories, [1]);
    expect(visible.map(c => c.categoryId)).toEqual([2, 3]);
  });

  it('should return children of deeply drilled category', () => {
    const visible = getVisibleCategories(categories, [1, 2]);
    expect(visible.map(c => c.categoryId)).toEqual([4]);
  });

  it('should return empty array when leaf category has no children', () => {
    const visible = getVisibleCategories(categories, [1, 2, 4]);
    expect(visible).toEqual([]);
  });
});

describe('getBreadcrumb', () => {
  it('should return only "All" for empty drillPath', () => {
    expect(getBreadcrumb(categories, [])).toEqual([
      { id: null, name: 'All' },
    ]);
  });

  it('should return All + category for single drill', () => {
    expect(getBreadcrumb(categories, [1])).toEqual([
      { id: null, name: 'All' },
      { id: 1, name: 'Rangefinders' },
    ]);
  });

  it('should return full breadcrumb for deep drill', () => {
    expect(getBreadcrumb(categories, [1, 2, 4])).toEqual([
      { id: null, name: 'All' },
      { id: 1, name: 'Rangefinders' },
      { id: 2, name: '35mm Film' },
      { id: 4, name: 'Leica' },
    ]);
  });
});

describe('getChildCount', () => {
  it('should return number of direct children', () => {
    expect(getChildCount(categories, 1)).toBe(2);
  });

  it('should return 0 for leaf category', () => {
    expect(getChildCount(categories, 4)).toBe(0);
  });

  it('should return 0 for unknown category', () => {
    expect(getChildCount(categories, 999)).toBe(0);
  });
});
