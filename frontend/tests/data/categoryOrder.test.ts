import { describe, it, expect } from 'vitest';
import { computeReorderUpdates, compareCategories } from '../../src/data/categories/categoryOrder';
import { createMockCategory } from '../testUtils';

describe('category ordering', () => {
  const categories = [
    createMockCategory({ categoryId: 1, name: 'Root A', parentCategoryId: null, sortOrder: 0 }),
    createMockCategory({ categoryId: 2, name: 'Child A1', parentCategoryId: 1, sortOrder: 0 }),
    createMockCategory({ categoryId: 3, name: 'Child A2', parentCategoryId: 1, sortOrder: 1 }),
    createMockCategory({ categoryId: 4, name: 'Grandchild A1a', parentCategoryId: 2, sortOrder: 0 }),
    createMockCategory({ categoryId: 5, name: 'Root B', parentCategoryId: null, sortOrder: 1 }),
  ];

  describe('computeReorderUpdates', () => {
    it('inserts before target when moving forward (insertAfter=false)', () => {
      const siblings = [
        createMockCategory({ categoryId: 10, parentCategoryId: null, sortOrder: 0, name: 'A' }),
        createMockCategory({ categoryId: 11, parentCategoryId: null, sortOrder: 1, name: 'B' }),
        createMockCategory({ categoryId: 12, parentCategoryId: null, sortOrder: 2, name: 'C' }),
      ];
      // Move A before C → B, A, C
      const updates = computeReorderUpdates(siblings, 10, 12, false);
      expect(updates).not.toBeNull();
      expect(updates).toEqual([
        { categoryId: 11, sortOrder: 0 },
        { categoryId: 10, sortOrder: 1 },
        { categoryId: 12, sortOrder: 2 },
      ]);
    });

    it('inserts after target when moving forward (insertAfter=true)', () => {
      const siblings = [
        createMockCategory({ categoryId: 10, parentCategoryId: null, sortOrder: 0, name: 'A' }),
        createMockCategory({ categoryId: 11, parentCategoryId: null, sortOrder: 1, name: 'B' }),
        createMockCategory({ categoryId: 12, parentCategoryId: null, sortOrder: 2, name: 'C' }),
      ];
      // Move A after C → B, C, A
      const updates = computeReorderUpdates(siblings, 10, 12, true);
      expect(updates).not.toBeNull();
      expect(updates).toEqual([
        { categoryId: 11, sortOrder: 0 },
        { categoryId: 12, sortOrder: 1 },
        { categoryId: 10, sortOrder: 2 },
      ]);
    });

    it('inserts before target when moving backward (insertAfter=false)', () => {
      const siblings = [
        createMockCategory({ categoryId: 10, parentCategoryId: null, sortOrder: 0, name: 'A' }),
        createMockCategory({ categoryId: 11, parentCategoryId: null, sortOrder: 1, name: 'B' }),
        createMockCategory({ categoryId: 12, parentCategoryId: null, sortOrder: 2, name: 'C' }),
      ];
      // Move C before A → C, A, B
      const updates = computeReorderUpdates(siblings, 12, 10, false);
      expect(updates).not.toBeNull();
      expect(updates).toEqual([
        { categoryId: 12, sortOrder: 0 },
        { categoryId: 10, sortOrder: 1 },
        { categoryId: 11, sortOrder: 2 },
      ]);
    });

    it('inserts after target when moving backward (insertAfter=true)', () => {
      const siblings = [
        createMockCategory({ categoryId: 10, parentCategoryId: null, sortOrder: 0, name: 'A' }),
        createMockCategory({ categoryId: 11, parentCategoryId: null, sortOrder: 1, name: 'B' }),
        createMockCategory({ categoryId: 12, parentCategoryId: null, sortOrder: 2, name: 'C' }),
      ];
      // Move C after A → A, C, B
      const updates = computeReorderUpdates(siblings, 12, 10, true);
      expect(updates).not.toBeNull();
      expect(updates).toEqual([
        { categoryId: 10, sortOrder: 0 },
        { categoryId: 12, sortOrder: 1 },
        { categoryId: 11, sortOrder: 2 },
      ]);
    });

    it('returns null when active item is not found', () => {
      const updates = computeReorderUpdates(categories, 999, 5);
      expect(updates).toBeNull();
    });

    it('returns null when over item is not a sibling', () => {
      // Category 1 (root) and category 4 (child of 2) are not siblings
      const updates = computeReorderUpdates(categories, 1, 4);
      expect(updates).toBeNull();
    });

    it('returns null when dragging onto itself', () => {
      const siblings = [
        createMockCategory({ categoryId: 10, parentCategoryId: null, sortOrder: 0 }),
        createMockCategory({ categoryId: 11, parentCategoryId: null, sortOrder: 1 }),
      ];
      const updates = computeReorderUpdates(siblings, 10, 10);
      expect(updates).toBeNull();
    });

    it('excludes system categories from reorder computation', () => {
      const cats = [
        createMockCategory({ categoryId: 10, parentCategoryId: null, sortOrder: 0, isSystem: true, name: 'System' }),
        createMockCategory({ categoryId: 11, parentCategoryId: null, sortOrder: 1, name: 'A' }),
        createMockCategory({ categoryId: 12, parentCategoryId: null, sortOrder: 2, name: 'B' }),
      ];
      // Reorder among non-system siblings
      const updates = computeReorderUpdates(cats, 12, 11);
      expect(updates).not.toBeNull();
      // System category should not appear in updates
      expect(updates!.find(u => u.categoryId === 10)).toBeUndefined();
      expect(updates).toEqual([
        { categoryId: 12, sortOrder: 0 },
        { categoryId: 11, sortOrder: 1 },
      ]);
    });

    it('computes reorder for children under the same parent', () => {
      // Children under parent 1: categories 2 (sortOrder 0) and 3 (sortOrder 1)
      const updates = computeReorderUpdates(categories, 3, 2);
      expect(updates).not.toBeNull();
      // Expected: Child A2 moves before Child A1
      expect(updates).toEqual([
        { categoryId: 3, sortOrder: 0 },
        { categoryId: 2, sortOrder: 1 },
      ]);
    });
  });

});

it('orders ties consistently and never includes foreign collections or workspaces in a reorder', () => {
  const a = createMockCategory({ categoryId: 1, name: 'B', sortOrder: 1 });
  const b = createMockCategory({ categoryId: 2, name: 'A', sortOrder: 1 });
  const c = createMockCategory({ categoryId: 3, name: 'A', sortOrder: 1 });
  expect([a, c, b].sort(compareCategories).map(value => value.categoryId)).toEqual([2, 3, 1]);
  const foreignCollection = createMockCategory({ categoryId: 4, collectionId: 2 });
  const foreignWorkspace = createMockCategory({ categoryId: 5, workspaceId: 2 });
  expect(computeReorderUpdates([a, b, foreignCollection, foreignWorkspace], 1, 2)).toEqual([
    { categoryId: 1, sortOrder: 0 }, { categoryId: 2, sortOrder: 1 },
  ]);
  expect(computeReorderUpdates([a, foreignCollection], 1, 4)).toBeNull();
  expect(computeReorderUpdates([createMockCategory({ categoryId: 99, isSystem: true }), a], 99, 1)).toBeNull();
});
