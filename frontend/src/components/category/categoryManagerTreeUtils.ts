import type { Category, CategoryNode } from '../../utils/types';

export interface FlatRow {
  category: Category;
  depth: number;
  hasChildren: boolean;
  rootIndex: number;
}

export function buildCategoryTree(categories: Category[]): CategoryNode[] {
  const map = new Map<number, CategoryNode>();
  const roots: CategoryNode[] = [];

  for (const cat of categories) {
    map.set(cat.categoryId, { ...cat, children: [] });
  }

  for (const cat of categories) {
    const node = map.get(cat.categoryId)!;
    if (cat.parentCategoryId === null) {
      roots.push(node);
    } else {
      const parent = map.get(cat.parentCategoryId);
      if (parent) {
        parent.children.push(node);
      } else {
        roots.push(node);
      }
    }
  }

  return roots;
}

export function flattenWithIndent(
  nodes: CategoryNode[],
  rootIndex: number,
  depth = 0
): FlatRow[] {
  const result: FlatRow[] = [];
  for (const node of nodes) {
    result.push({
      category: node,
      depth,
      hasChildren: node.children.length > 0,
      rootIndex,
    });
    if (node.children.length > 0) {
      result.push(...flattenWithIndent(node.children, rootIndex, depth + 1));
    }
  }
  return result;
}

export function getDescendantIds(categories: Category[], categoryId: number): Set<number> {
  const descendants = new Set<number>();
  const queue = [categoryId];
  while (queue.length > 0) {
    const current = queue.pop()!;
    for (const cat of categories) {
      if (cat.parentCategoryId === current && !descendants.has(cat.categoryId)) {
        descendants.add(cat.categoryId);
        queue.push(cat.categoryId);
      }
    }
  }
  return descendants;
}

/**
 * Compute reorder updates when dragging within the same parent group.
 * Returns null if the reorder is invalid (indices not found or same position).
 */
export function computeReorderUpdates(
  categories: Category[],
  activeId: number,
  overId: number
): { categoryId: number; sortOrder: number }[] | null {
  const activeItem = categories.find(c => c.categoryId === activeId);
  if (!activeItem) return null;

  const parentId = activeItem.parentCategoryId;
  const siblings = categories
    .filter(c => c.parentCategoryId === parentId && !c.isSystem)
    .sort((a, b) => a.sortOrder - b.sortOrder);

  const oldIndex = siblings.findIndex(c => c.categoryId === activeId);
  const newIndex = siblings.findIndex(c => c.categoryId === overId);
  if (oldIndex === -1 || newIndex === -1 || oldIndex === newIndex) return null;

  const reordered = [...siblings];
  const [moved] = reordered.splice(oldIndex, 1);
  reordered.splice(newIndex, 0, moved);

  return reordered.map((cat, idx) => ({
    categoryId: cat.categoryId,
    sortOrder: idx,
  }));
}

/**
 * Determine the reparent target when dropping onto a category with a different parent.
 * If the over item has children, reparent into it; otherwise reparent to the over item's parent.
 * Returns null if the items share the same parent (not a reparent operation).
 */
export function determineReparentTarget(
  categories: Category[],
  activeId: number,
  overId: number
): number | null | undefined {
  const activeItem = categories.find(c => c.categoryId === activeId);
  const overItem = categories.find(c => c.categoryId === overId);
  if (!activeItem || !overItem) return undefined;

  // Same parent means reorder, not reparent
  if (activeItem.parentCategoryId === overItem.parentCategoryId) return undefined;

  const overHasChildren = categories.some(c => c.parentCategoryId === overId);
  if (overHasChildren) {
    return overId;
  }
  return overItem.parentCategoryId;
}
