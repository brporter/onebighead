import { describe, it, expect } from 'vitest';
import {
  buildCategoryTree,
  flattenWithIndent,
  getDescendantIds,
  computeReorderUpdates,
  determineReparentTarget,
} from '../src/components/category/categoryManagerTreeUtils';
import { createMockCategory } from './testUtils';

describe('categoryManagerTreeUtils', () => {
  // Shared category hierarchy for most tests:
  //   1: Root A (parent: null, sortOrder: 0)
  //   2: Child A1 (parent: 1, sortOrder: 0)
  //   3: Child A2 (parent: 1, sortOrder: 1)
  //   4: Grandchild A1a (parent: 2, sortOrder: 0)
  //   5: Root B (parent: null, sortOrder: 1)
  const categories = [
    createMockCategory({ categoryId: 1, name: 'Root A', parentCategoryId: null, sortOrder: 0 }),
    createMockCategory({ categoryId: 2, name: 'Child A1', parentCategoryId: 1, sortOrder: 0 }),
    createMockCategory({ categoryId: 3, name: 'Child A2', parentCategoryId: 1, sortOrder: 1 }),
    createMockCategory({ categoryId: 4, name: 'Grandchild A1a', parentCategoryId: 2, sortOrder: 0 }),
    createMockCategory({ categoryId: 5, name: 'Root B', parentCategoryId: null, sortOrder: 1 }),
  ];

  describe('buildCategoryTree', () => {
    it('builds a tree with root nodes at the top level', () => {
      const tree = buildCategoryTree(categories);
      expect(tree).toHaveLength(2);
      expect(tree[0].name).toBe('Root A');
      expect(tree[1].name).toBe('Root B');
    });

    it('nests children under their parents', () => {
      const tree = buildCategoryTree(categories);
      const rootA = tree[0];
      expect(rootA.children).toHaveLength(2);
      expect(rootA.children[0].name).toBe('Child A1');
      expect(rootA.children[1].name).toBe('Child A2');
    });

    it('nests grandchildren correctly', () => {
      const tree = buildCategoryTree(categories);
      const childA1 = tree[0].children[0];
      expect(childA1.children).toHaveLength(1);
      expect(childA1.children[0].name).toBe('Grandchild A1a');
    });

    it('returns empty array for empty input', () => {
      const tree = buildCategoryTree([]);
      expect(tree).toHaveLength(0);
    });

    it('treats orphaned categories (missing parent) as roots', () => {
      const orphaned = [
        createMockCategory({ categoryId: 10, name: 'Orphan', parentCategoryId: 999 }),
      ];
      const tree = buildCategoryTree(orphaned);
      expect(tree).toHaveLength(1);
      expect(tree[0].name).toBe('Orphan');
    });

    it('handles leaf-only categories with no children', () => {
      const tree = buildCategoryTree(categories);
      const rootB = tree[1];
      expect(rootB.children).toHaveLength(0);
    });
  });

  describe('flattenWithIndent', () => {
    it('flattens a tree into rows with correct depths', () => {
      const tree = buildCategoryTree(categories);
      const rows = flattenWithIndent([tree[0]], 0);
      expect(rows).toHaveLength(4); // Root A, Child A1, Grandchild A1a, Child A2
      expect(rows[0].depth).toBe(0);
      expect(rows[0].category.name).toBe('Root A');
      expect(rows[1].depth).toBe(1);
      expect(rows[1].category.name).toBe('Child A1');
      expect(rows[2].depth).toBe(2);
      expect(rows[2].category.name).toBe('Grandchild A1a');
      expect(rows[3].depth).toBe(1);
      expect(rows[3].category.name).toBe('Child A2');
    });

    it('sets hasChildren correctly', () => {
      const tree = buildCategoryTree(categories);
      const rows = flattenWithIndent([tree[0]], 0);
      expect(rows[0].hasChildren).toBe(true); // Root A has children
      expect(rows[1].hasChildren).toBe(true); // Child A1 has Grandchild A1a
      expect(rows[2].hasChildren).toBe(false); // Grandchild A1a is a leaf
      expect(rows[3].hasChildren).toBe(false); // Child A2 is a leaf
    });

    it('assigns rootIndex to all rows', () => {
      const tree = buildCategoryTree(categories);
      const rows = flattenWithIndent([tree[0]], 3);
      for (const row of rows) {
        expect(row.rootIndex).toBe(3);
      }
    });

    it('returns empty array for empty nodes', () => {
      const rows = flattenWithIndent([], 0);
      expect(rows).toHaveLength(0);
    });

    it('handles a single leaf node', () => {
      const tree = buildCategoryTree(categories);
      const rows = flattenWithIndent([tree[1]], 1); // Root B (leaf)
      expect(rows).toHaveLength(1);
      expect(rows[0].depth).toBe(0);
      expect(rows[0].hasChildren).toBe(false);
    });
  });

  describe('getDescendantIds', () => {
    it('returns all descendants of a root category', () => {
      const descendants = getDescendantIds(categories, 1);
      expect(descendants).toEqual(new Set([2, 3, 4]));
    });

    it('returns descendants of a mid-level category', () => {
      const descendants = getDescendantIds(categories, 2);
      expect(descendants).toEqual(new Set([4]));
    });

    it('returns empty set for a leaf category', () => {
      const descendants = getDescendantIds(categories, 4);
      expect(descendants.size).toBe(0);
    });

    it('returns empty set for a category with no children', () => {
      const descendants = getDescendantIds(categories, 5);
      expect(descendants.size).toBe(0);
    });

    it('returns empty set for a non-existent category', () => {
      const descendants = getDescendantIds(categories, 999);
      expect(descendants.size).toBe(0);
    });

    it('handles deeply nested hierarchies', () => {
      const deep = [
        createMockCategory({ categoryId: 10, parentCategoryId: null }),
        createMockCategory({ categoryId: 11, parentCategoryId: 10 }),
        createMockCategory({ categoryId: 12, parentCategoryId: 11 }),
        createMockCategory({ categoryId: 13, parentCategoryId: 12 }),
      ];
      const descendants = getDescendantIds(deep, 10);
      expect(descendants).toEqual(new Set([11, 12, 13]));
    });
  });

  describe('computeReorderUpdates', () => {
    it('computes correct sort orders when moving item forward', () => {
      // Three siblings under root (parent: null)
      const siblings = [
        createMockCategory({ categoryId: 10, parentCategoryId: null, sortOrder: 0, name: 'A' }),
        createMockCategory({ categoryId: 11, parentCategoryId: null, sortOrder: 1, name: 'B' }),
        createMockCategory({ categoryId: 12, parentCategoryId: null, sortOrder: 2, name: 'C' }),
      ];
      // Move A (index 0) to where C is (index 2)
      const updates = computeReorderUpdates(siblings, 10, 12);
      expect(updates).not.toBeNull();
      // Expected order: B(0), C(1), A(2)
      expect(updates).toEqual([
        { categoryId: 11, sortOrder: 0 },
        { categoryId: 12, sortOrder: 1 },
        { categoryId: 10, sortOrder: 2 },
      ]);
    });

    it('computes correct sort orders when moving item backward', () => {
      const siblings = [
        createMockCategory({ categoryId: 10, parentCategoryId: null, sortOrder: 0, name: 'A' }),
        createMockCategory({ categoryId: 11, parentCategoryId: null, sortOrder: 1, name: 'B' }),
        createMockCategory({ categoryId: 12, parentCategoryId: null, sortOrder: 2, name: 'C' }),
      ];
      // Move C (index 2) to where A is (index 0)
      const updates = computeReorderUpdates(siblings, 12, 10);
      expect(updates).not.toBeNull();
      // Expected order: C(0), A(1), B(2)
      expect(updates).toEqual([
        { categoryId: 12, sortOrder: 0 },
        { categoryId: 10, sortOrder: 1 },
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

  describe('determineReparentTarget', () => {
    it('reparents into a category that has children', () => {
      // Dragging Root B (id: 5, parent: null) onto Child A1 (id: 2, parent: 1)
      // Child A1 has children (Grandchild A1a), so target should be 2
      const target = determineReparentTarget(categories, 5, 2);
      expect(target).toBe(2);
    });

    it('reparents to the over item parent when over item has no children', () => {
      // Dragging Root B (id: 5, parent: null) onto Child A2 (id: 3, parent: 1)
      // Child A2 has no children, so target is its parent (1)
      const target = determineReparentTarget(categories, 5, 3);
      expect(target).toBe(1);
    });

    it('returns undefined when items share the same parent (reorder, not reparent)', () => {
      // Both categories 2 and 3 have parent 1
      const target = determineReparentTarget(categories, 2, 3);
      expect(target).toBeUndefined();
    });

    it('returns undefined when active item is not found', () => {
      const target = determineReparentTarget(categories, 999, 2);
      expect(target).toBeUndefined();
    });

    it('returns undefined when over item is not found', () => {
      const target = determineReparentTarget(categories, 1, 999);
      expect(target).toBeUndefined();
    });

    it('reparents to null when over item is a root leaf', () => {
      // Dragging Grandchild A1a (id: 4, parent: 2) onto Root B (id: 5, parent: null)
      // Root B has no children, so target is its parent (null)
      const target = determineReparentTarget(categories, 4, 5);
      expect(target).toBeNull();
    });

    it('reparents into root node that has children', () => {
      // Dragging Root B (id: 5, parent: null) onto Root A (id: 1, parent: null)
      // But they share the same parent (null), so it should be undefined (reorder case)
      const target = determineReparentTarget(categories, 5, 1);
      expect(target).toBeUndefined();
    });

    it('reparents a grandchild into a different subtree', () => {
      // Create a scenario with two separate subtrees
      const cats = [
        createMockCategory({ categoryId: 1, parentCategoryId: null, sortOrder: 0 }),
        createMockCategory({ categoryId: 2, parentCategoryId: 1, sortOrder: 0 }),
        createMockCategory({ categoryId: 3, parentCategoryId: null, sortOrder: 1 }),
        createMockCategory({ categoryId: 4, parentCategoryId: 3, sortOrder: 0 }),
        createMockCategory({ categoryId: 5, parentCategoryId: 4, sortOrder: 0 }),
      ];
      // Drag category 2 (parent: 1) onto category 4 (parent: 3, has child 5)
      const target = determineReparentTarget(cats, 2, 4);
      expect(target).toBe(4); // 4 has children, so reparent into it
    });
  });
});
