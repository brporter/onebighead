import type { Category } from '../../utils/types';

export function compareCategories(left: Category, right: Category): number {
  return left.sortOrder - right.sortOrder || left.name.localeCompare(right.name) || left.categoryId - right.categoryId;
}

/**
 * Compute reorder updates when dragging within the same parent group.
 * `insertAfter` controls whether the item is placed before or after the target.
 * Returns null if the reorder is invalid (indices not found or same position).
 */
export function computeReorderUpdates(
  categories: Category[],
  activeId: number,
  overId: number,
  insertAfter = false
): { categoryId: number; sortOrder: number }[] | null {
  const activeItem = categories.find(c => c.categoryId === activeId);
  if (!activeItem) return null;

  const parentId = activeItem.parentCategoryId;
  const siblings = categories
    .filter(c => c.parentCategoryId === parentId && !c.isSystem &&
      c.collectionId === activeItem.collectionId && c.workspaceId === activeItem.workspaceId)
    .sort(compareCategories);

  const oldIndex = siblings.findIndex(c => c.categoryId === activeId);
  const overIndex = siblings.findIndex(c => c.categoryId === overId);
  if (oldIndex === -1 || overIndex === -1 || oldIndex === overIndex) return null;

  const reordered = [...siblings];
  const [moved] = reordered.splice(oldIndex, 1);

  // After removing the active item, compute the insertion index
  // The overIndex may have shifted if the active item was before it
  let insertIndex = overIndex > oldIndex ? overIndex - 1 : overIndex;
  if (insertAfter) {
    insertIndex += 1;
  }
  reordered.splice(insertIndex, 0, moved);

  return reordered.map((cat, idx) => ({
    categoryId: cat.categoryId,
    sortOrder: idx,
  }));
}

