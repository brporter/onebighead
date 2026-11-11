import type { ThemeCategory } from '../../utils/types';

export interface ThemeCategoryPreviewRow {
  category: ThemeCategory;
  sourceIndex: number;
  depth: number;
}

/** Theme parents are names, not persisted category IDs. Never guess an ambiguous link. */
export function themeCategoryPreview(categories: readonly ThemeCategory[]) {
  const ordered = categories.map((category, sourceIndex) => ({ category, sourceIndex, depth: 0 }))
    .sort((a, b) => a.category.sortOrder - b.category.sortOrder || a.category.name.localeCompare(b.category.name));
  const names = new Set(categories.map(category => category.name.trim()));
  const flat = { rows: ordered, hierarchyAvailable: false };
  if (names.size !== categories.length) return flat;

  const children = new Map<string | null, ThemeCategoryPreviewRow[]>();
  for (const row of ordered) {
    const parent = row.category.parentName?.trim() || null;
    if (parent !== null && !names.has(parent)) return flat;
    const siblings = children.get(parent) ?? [];
    siblings.push(row);
    children.set(parent, siblings);
  }

  // Every name has one parent. Unique names keep cycles disconnected from roots.
  // Iteration also keeps deeply nested themes from exhausting the call stack.
  const pending = [...(children.get(null) ?? [])].reverse();
  const rows: ThemeCategoryPreviewRow[] = [];
  while (pending.length > 0) {
    const row = pending.pop()!;
    rows.push(row);
    const descendants = children.get(row.category.name.trim()) ?? [];
    for (let index = descendants.length - 1; index >= 0; index--) {
      pending.push({ ...descendants[index], depth: row.depth + 1 });
    }
  }

  return rows.length === categories.length ? { rows, hierarchyAvailable: true } : flat;
}
