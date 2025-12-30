import type { Category } from './types';

export function getCategoryAndDescendantIds(categories: Category[], selectedCategoryId: number | null): Set<number> {
  if (selectedCategoryId == null) return new Set();

  const childrenByParent = new Map<number | null, number[]>();
  for (const cat of categories) {
    const parentId = cat.parentCategoryId ?? null;
    if (!childrenByParent.has(parentId)) childrenByParent.set(parentId, []);
    childrenByParent.get(parentId)!.push(cat.categoryId);
  }

  const result = new Set<number>();
  const stack: (number | null)[] = [selectedCategoryId];

  while (stack.length) {
    const id = stack.pop();
    if (id == null || result.has(id)) continue;
    result.add(id);

    const children = childrenByParent.get(id);
    if (children?.length) {
      for (const childId of children) stack.push(childId);
    }
  }

  return result;
}

