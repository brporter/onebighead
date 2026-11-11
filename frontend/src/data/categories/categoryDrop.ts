import type { Category } from '../../utils/types';
import { CategoryHierarchy } from './CategoryHierarchy';
import { compareCategories, computeReorderUpdates } from './categoryOrder';

export type DropIntent = 'reparent' | 'reorder-before' | 'reorder-after';
export type CategoryMove =
  | { type: 'reorder'; updates: { categoryId: number; sortOrder: number }[] }
  | { type: 'reparent'; categoryId: number; parentId: number | null; insertAtCategoryId?: number; insertAfter?: boolean };

/** Top/bottom edges insert among siblings; the center nests under the target. */
export function getDropIntent(rect: { top: number; height: number }, pointerY: number): DropIntent {
  const relative = (pointerY - rect.top) / rect.height;
  if (relative <= 0.1) return 'reorder-before';
  if (relative >= 0.9) return 'reorder-after';
  return 'reparent';
}

/** A shared decision for pointer previews, keyboard moves and the final drop. */
export function resolveCategoryDrop(categories: Category[], activeId: number, targetId: number | 'root-drop-zone', intent: DropIntent): CategoryMove | null {
  const active = categories.find(category => category.categoryId === activeId);
  if (!active || active.isSystem) return null;
  if (targetId === 'root-drop-zone')
    return active.parentCategoryId === null ? null : { type: 'reparent', categoryId: activeId, parentId: null };

  const hierarchy = new CategoryHierarchy(categories);
  const target = categories.find(category => category.categoryId === targetId);
  if (!target || target.isSystem || target.collectionId !== active.collectionId || target.workspaceId !== active.workspaceId ||
      hierarchy.descendantIds(activeId).has(targetId)) return null;
  if (intent === 'reparent')
    return !hierarchy.canBeParent(targetId) || active.parentCategoryId === targetId ? null : { type: 'reparent', categoryId: activeId, parentId: targetId };

  if (target.parentCategoryId !== null && !hierarchy.canBeParent(target.parentCategoryId)) return null;
  const insertAfter = intent === 'reorder-after';
  if (active.parentCategoryId !== target.parentCategoryId)
    return { type: 'reparent', categoryId: activeId, parentId: target.parentCategoryId, insertAtCategoryId: targetId, insertAfter };
  const scoped = categories.filter(category => category.collectionId === active.collectionId && category.workspaceId === active.workspaceId);
  const updates = computeReorderUpdates(scoped, activeId, targetId, insertAfter)!;
  const siblings = scoped.filter(category => !category.isSystem && category.parentCategoryId === active.parentCategoryId)
    .sort(compareCategories);
  return updates.every((update, index) => update.categoryId === siblings[index].categoryId) ? null : { type: 'reorder', updates };
}
