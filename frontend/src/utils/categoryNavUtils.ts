import type { Category } from './types';

export interface BreadcrumbSegment {
  id: number | null;
  name: string;
}

export function buildDrillPath(categories: Category[], categoryId: number | null): number[] {
  if (categoryId === null) return [];

  const byId = new Map<number, Category>();
  for (const cat of categories) {
    byId.set(cat.categoryId, cat);
  }

  const target = byId.get(categoryId);
  if (!target) return [];

  const path: number[] = [];
  let current: Category | undefined = target;
  while (current) {
    path.unshift(current.categoryId);
    current = current.parentCategoryId !== null ? byId.get(current.parentCategoryId) : undefined;
  }
  return path;
}

export function getVisibleCategories(categories: Category[], drillPath: number[]): Category[] {
  if (drillPath.length === 0) {
    return categories.filter(c => c.parentCategoryId === null);
  }
  const currentId = drillPath[drillPath.length - 1];
  return categories.filter(c => c.parentCategoryId === currentId);
}

export function getBreadcrumb(categories: Category[], drillPath: number[]): BreadcrumbSegment[] {
  const byId = new Map<number, Category>();
  for (const cat of categories) {
    byId.set(cat.categoryId, cat);
  }

  const crumbs: BreadcrumbSegment[] = [{ id: null, name: 'All' }];
  for (const catId of drillPath) {
    const cat = byId.get(catId);
    if (cat) crumbs.push({ id: cat.categoryId, name: cat.name });
  }
  return crumbs;
}

export function getChildCount(categories: Category[], categoryId: number): number {
  return categories.filter(c => c.parentCategoryId === categoryId).length;
}
