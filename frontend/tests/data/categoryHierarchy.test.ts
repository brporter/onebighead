import { expect, it } from 'vitest';
import { CategoryHierarchy } from '../../src/data/categories/CategoryHierarchy';
import { createMockCategory as category } from '../testUtils';

it('shares ordered rows, roots, breadcrumbs, colors and descendant membership', () => {
  const source = [
    category({ categoryId: 5, name: 'Root B', sortOrder: 1 }),
    category({ categoryId: 3, name: 'Child B', parentCategoryId: 1, sortOrder: 1 }),
    category({ categoryId: 4, name: 'Grandchild', parentCategoryId: 2 }),
    category({ categoryId: 1, name: 'Root A' }),
    category({ categoryId: 2, name: 'Child A', parentCategoryId: 1 }),
  ];
  const tree = new CategoryHierarchy(source);
  expect(tree.rows.map(row => row.category.categoryId)).toEqual([1, 2, 4, 3, 5]);
  expect(tree.rows.map(row => row.depth)).toEqual([0, 1, 2, 1, 0]);
  expect(tree.rows.map(row => row.hasChildren)).toEqual([true, true, false, false, false]);
  expect(tree.rows.map(row => row.rootIndex)).toEqual([0, 0, 0, 0, 1]);
  expect(tree.childrenOf(null).map(value => value.categoryId)).toEqual([1, 5]);
  expect(tree.childrenOf(1).map(value => value.categoryId)).toEqual([2, 3]);
  expect(tree.pathTo(4).map(value => value.categoryId)).toEqual([1, 2, 4]);
  expect(tree.pathTo(5).map(value => value.categoryId)).toEqual([5]);
  expect(tree.descendantIds(1)).toEqual(new Set([1, 2, 3, 4]));
  expect(tree.descendantIds(2)).toEqual(new Set([2, 4]));
  expect(tree.descendantIds(4)).toEqual(new Set([4]));
  expect(tree.rootIndex(4)).toBe(0);
  expect(tree.rootIndex(5)).toBe(1);
  expect(source.map(value => value.categoryId)).toEqual([5, 3, 4, 1, 2]);
  expect(tree.rows.every(row => tree.canBeParent(row.category.categoryId))).toBe(true);
});

it('shows missing and foreign parents as roots without allowing them as new parents', () => {
  const tree = new CategoryHierarchy([
    category({ categoryId: 1 }),
    category({ categoryId: 2, parentCategoryId: 99 }),
    category({ categoryId: 3, parentCategoryId: 1, collectionId: 2 }),
    category({ categoryId: 4, parentCategoryId: 1, workspaceId: 2 }),
    category({ categoryId: 5, parentCategoryId: 2 }),
    category({ categoryId: 6, isSystem: true }),
    category({ categoryId: 7, parentCategoryId: 6 }),
  ]);
  expect(tree.childrenOf(null).map(value => value.categoryId)).toEqual([1, 2, 3, 4, 6]);
  expect(tree.descendantIds(1)).toEqual(new Set([1]));
  expect(tree.pathTo(5).map(value => value.categoryId)).toEqual([2, 5]);
  expect(tree.byId.get(2)?.parentCategoryId).toBe(99);
  expect(tree.canBeParent(1)).toBe(true);
  for (const id of [2, 3, 4, 5, 6, 7, 99]) expect(tree.canBeParent(id)).toBe(false);
});

it('keeps every cyclic category visible once and retains original relationships for move safety', () => {
  const source = [
    category({ categoryId: 6, parentCategoryId: 4 }),
    category({ categoryId: 4, parentCategoryId: 2 }),
    category({ categoryId: 3, parentCategoryId: 1 }),
    category({ categoryId: 2, parentCategoryId: 3 }),
    category({ categoryId: 1, parentCategoryId: 2 }),
    category({ categoryId: 5 }),
    category({ categoryId: 7, parentCategoryId: 7 }),
  ];
  const tree = new CategoryHierarchy(source);
  expect(tree.rows.map(row => row.category.categoryId)).toEqual([1, 3, 2, 4, 6, 5, 7]);
  expect(tree.pathTo(6).map(value => value.categoryId)).toEqual([1, 3, 2, 4, 6]);
  expect(tree.descendantIds(2)).toEqual(new Set([1, 2, 3, 4, 6]));
  expect(tree.descendantIds(7)).toEqual(new Set([7]));
  expect(tree.pathTo(7).map(value => value.categoryId)).toEqual([7]);
  expect(tree.canBeParent(5)).toBe(true);
  for (const id of [1, 2, 3, 4, 6, 7]) expect(tree.canBeParent(id)).toBe(false);
  expect(source.find(value => value.categoryId === 1)?.parentCategoryId).toBe(2);
  expect(new CategoryHierarchy([...source].reverse()).rows.map(row => row.category.categoryId))
    .toEqual(tree.rows.map(row => row.category.categoryId));
});

it('handles 20,000 levels without recursion or repeated ancestor scanning', () => {
  const source = Array.from({ length: 20000 }, (_, index) => category({
    categoryId: index + 1, parentCategoryId: index === 0 ? null : index,
  })).reverse();
  const tree = new CategoryHierarchy(source);
  expect(tree.rows).toHaveLength(20000);
  expect(tree.rows.at(-1)?.depth).toBe(19999);
  expect(tree.pathTo(20000)).toHaveLength(20000);
  expect(tree.descendantIds(1).size).toBe(20000);
  expect(tree.canBeParent(20000)).toBe(true);
});

it('handles empty, missing and duplicate identities deterministically', () => {
  const empty = new CategoryHierarchy([]);
  expect(empty.rows).toEqual([]);
  expect(empty.childrenOf(null)).toEqual([]);
  expect(empty.childrenOf(99)).toEqual([]);
  expect(empty.pathTo(null)).toEqual([]);
  expect(empty.pathTo(99)).toEqual([]);
  expect(empty.descendantIds(null)).toEqual(new Set());
  expect(empty.descendantIds(99)).toEqual(new Set());
  expect(empty.rootIndex(99)).toBe(0);
  const duplicate = new CategoryHierarchy([category({ categoryId: 1 }), category({ categoryId: 1, name: 'Updated' })]);
  expect(duplicate.rows).toHaveLength(1);
  expect(duplicate.rows[0].category.name).toBe('Updated');
});
