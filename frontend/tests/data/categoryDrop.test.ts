import { describe, expect, it } from 'vitest';
import { getDropIntent, resolveCategoryDrop } from '../../src/data/categories/categoryDrop';
import { computeReorderUpdates } from '../../src/data/categories/categoryOrder';
import { createMockCategory as category } from '../testUtils';

const categories = [
  category({ categoryId: 1, name: 'Books', parentCategoryId: null, sortOrder: 0 }),
  category({ categoryId: 2, name: 'Cameras', parentCategoryId: null, sortOrder: 1 }),
  category({ categoryId: 3, name: 'Film', parentCategoryId: 2, sortOrder: 0 }),
  category({ categoryId: 4, name: 'Digital', parentCategoryId: 2, sortOrder: 1 }),
  category({ categoryId: 5, name: 'Archive', parentCategoryId: null, sortOrder: 2 }),
  category({ categoryId: 6, isSystem: true, parentCategoryId: null }),
  category({ categoryId: 7, collectionId: 99, parentCategoryId: null }),
  category({ categoryId: 8, workspaceId: 99, parentCategoryId: null }),
];

describe('category drop decisions', () => {
  it.each([[100, 'reorder-before'], [110, 'reorder-before'], [150, 'reparent'], [190, 'reorder-after'], [200, 'reorder-after']] as const)('maps pointer %s to %s', (pointer, intent) => expect(getDropIntent({ top: 100, height: 100 }, pointer)).toBe(intent));

  it.each([[99, 1], [6, 1], [1, 99], [1, 6], [1, 7], [1, 8], [1, 1], [2, 3], [2, 4]] as const)('rejects invalid move %s to %s', (active, target) => expect(resolveCategoryDrop(categories, active, target, 'reparent')).toBeNull());

  it('moves nested categories to root but ignores already-root and unchanged-parent drops', () => {
    expect(resolveCategoryDrop(categories, 3, 'root-drop-zone', 'reparent')).toEqual({ type: 'reparent', categoryId: 3, parentId: null });
    expect(resolveCategoryDrop(categories, 1, 'root-drop-zone', 'reparent')).toBeNull();
    expect(resolveCategoryDrop(categories, 3, 2, 'reparent')).toBeNull();
    expect(resolveCategoryDrop(categories, 1, 2, 'reparent')).toEqual({ type: 'reparent', categoryId: 1, parentId: 2 });
  });

  it('moves across parents relative to the selected sibling', () => {
    expect(resolveCategoryDrop(categories, 1, 3, 'reorder-before')).toEqual({ type: 'reparent', categoryId: 1, parentId: 2, insertAtCategoryId: 3, insertAfter: false });
    expect(resolveCategoryDrop(categories, 3, 1, 'reorder-after')).toEqual({ type: 'reparent', categoryId: 3, parentId: null, insertAtCategoryId: 1, insertAfter: true });
  });

  it('reorders only the active collection and workspace, excluding system categories and no-op insertions', () => {
    expect(resolveCategoryDrop(categories, 1, 2, 'reorder-before')).toBeNull();
    expect(resolveCategoryDrop(categories, 1, 2, 'reorder-after')).toEqual({ type: 'reorder', updates: [
      { categoryId: 2, sortOrder: 0 }, { categoryId: 1, sortOrder: 1 }, { categoryId: 5, sortOrder: 2 },
    ] });
    expect(resolveCategoryDrop(categories, 4, 3, 'reorder-before')).toEqual({ type: 'reorder', updates: [
      { categoryId: 4, sortOrder: 0 }, { categoryId: 3, sortOrder: 1 },
    ] });
    expect(computeReorderUpdates(categories, 6, 1)).toBeNull();
  });
});

it('rejects corrupt ancestry as a drop destination while allowing a root repair', () => {
  const source = [category({ categoryId: 1 }), category({ categoryId: 2, parentCategoryId: 3 }),
    category({ categoryId: 3, parentCategoryId: 2 }), category({ categoryId: 4, parentCategoryId: 99 })];
  expect(resolveCategoryDrop(source, 1, 2, 'reparent')).toBeNull();
  expect(resolveCategoryDrop(source, 1, 2, 'reorder-before')).toBeNull();
  expect(resolveCategoryDrop(source, 1, 4, 'reparent')).toBeNull();
  expect(resolveCategoryDrop(source, 1, 4, 'reorder-after')).toBeNull();
  expect(resolveCategoryDrop(source, 2, 'root-drop-zone', 'reparent')).toEqual({ type: 'reparent', categoryId: 2, parentId: null });
});
