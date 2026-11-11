import { expect, it } from 'vitest';
import { themeCategoryPreview } from '../../src/data/themes/themeCategoryPreview';
import { createMockThemeCategory as category } from '../testUtils/factories';

it('sorts siblings by order and name, keeping children beneath their parent without mutating source data', () => {
  const categories = Object.freeze([
    category({ name: 'Zines', sortOrder: 1 }),
    category({ name: 'Verse', parentName: 'Books', sortOrder: 1 }),
    category({ name: 'Fiction', parentName: 'Books', sortOrder: 1 }),
    category({ name: 'Books', sortOrder: 1 }),
    category({ name: 'Comics', parentName: '', sortOrder: 0 }),
    category({ name: 'Rare', parentName: 'Fiction' }),
  ].map(value => Object.freeze(value)));
  const result = themeCategoryPreview(categories);
  expect(result.hierarchyAvailable).toBe(true);
  expect(result.rows.map(row => [row.category.name, row.depth, row.sourceIndex])).toEqual([
    ['Comics', 0, 4], ['Books', 0, 3], ['Fiction', 1, 2], ['Rare', 2, 5], ['Verse', 1, 1], ['Zines', 0, 0],
  ]);
  expect(result.rows[3].category).toBe(categories[5]);
  expect(categories[0].name).toBe('Zines');
});

it.each([
  [category({ name: 'Root' }), category({ name: 'Root', parentName: 'Root' })],
  [category({ name: 'Orphan', parentName: 'Missing' })],
  [category({ name: 'Self', parentName: 'Self' })],
  [category({ name: 'Root' }), category({ name: 'A', parentName: 'B' }), category({ name: 'B', parentName: 'A' }), category({ name: 'C', parentName: 'B' })],
])('preserves every category in a flat fallback when names do not define an unambiguous rooted hierarchy: %j', (...categories) => {
  const result = themeCategoryPreview(categories);
  expect(result.hierarchyAvailable).toBe(false);
  expect(result.rows).toHaveLength(categories.length);
  expect(new Set(result.rows.map(row => row.sourceIndex)).size).toBe(categories.length);
  for (const row of result.rows) {
    expect(row.depth).toBe(0);
    expect(row.category).toBe(categories[row.sourceIndex]);
  }
});

it('handles an empty theme and a deep, reverse-ordered theme without recursive traversal', () => {
  expect(themeCategoryPreview([])).toEqual({ rows: [], hierarchyAvailable: true });
  const categories = Array.from({ length: 20_000 }, (_, index) => category({
    name: String(index), parentName: index === 0 ? null : String(index - 1),
  })).reverse();
  const result = themeCategoryPreview(categories);
  expect(result.hierarchyAvailable).toBe(true);
  expect(result.rows).toHaveLength(20_000);
  expect(result.rows[0]).toEqual({ category: categories[19_999], sourceIndex: 19_999, depth: 0 });
  expect(result.rows[19_999]).toEqual({ category: categories[0], sourceIndex: 0, depth: 19_999 });
});

it('matches the setup contract: trim names, treat blank parents as roots, and preserve case', () => {
  const parent = category({ name: ' Root ', parentName: '  ' });
  const child = category({ name: 'Child', parentName: ' Root ' });
  expect(themeCategoryPreview([child, parent])).toEqual({ hierarchyAvailable: true, rows: [
    { category: parent, sourceIndex: 1, depth: 0 }, { category: child, sourceIndex: 0, depth: 1 },
  ] });
  expect(themeCategoryPreview([parent, category({ name: 'Root' })]).hierarchyAvailable).toBe(false);
  expect(themeCategoryPreview([parent, category({ name: 'Child', parentName: 'root' })]).hierarchyAvailable).toBe(false);
});
