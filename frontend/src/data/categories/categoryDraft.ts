import type { Category } from '../../utils/types';
import { CategoryHierarchy } from './CategoryHierarchy';

export interface CategoryDraft {
  name: string;
  description: string;
  parentCategoryId: number | null;
  itemTemplateIds: number[];
}

export function validateCategoryName(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return 'Name is required';
  if (trimmed.toLowerCase() === 'unassigned items') return `"${trimmed}" is a reserved name and cannot be used`;
  return null;
}

export function availableCategoryParents(categories: Category[], collectionId: number, category: Category | null) {
  const scoped = categories.filter(candidate => candidate.collectionId === collectionId && !candidate.isSystem);
  const hierarchy = new CategoryHierarchy(scoped);
  const excluded = hierarchy.descendantIds(category?.categoryId ?? null);
  return scoped.filter(candidate => hierarchy.canBeParent(candidate.categoryId) && !excluded.has(candidate.categoryId));
}
