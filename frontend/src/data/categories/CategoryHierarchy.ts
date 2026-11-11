import type { Category } from '../../utils/types';
import { compareCategories } from './categoryOrder';

export interface CategoryRow {
  category: Category;
  depth: number;
  hasChildren: boolean;
  rootIndex: number;
}

/** Read-only projection. Display recovery never changes the stored parent relationships. */
export class CategoryHierarchy {
  readonly byId: ReadonlyMap<number, Category>;
  readonly rows: CategoryRow[] = [];
  private readonly parents = new Map<number, number | null>();
  private readonly children = new Map<number | null, Category[]>([[null, []]]);
  private readonly sourceChildren = new Map<number, number[]>();
  private readonly validAncestry = new Map<number, boolean>();
  private readonly rootIndices = new Map<number, number>();

  constructor(categories: readonly Category[]) {
    this.byId = new Map(categories.map(category => [category.categoryId, category]));
    const invalid = new Set<number>();
    for (const category of this.byId.values()) {
      const parent = category.parentCategoryId === null ? undefined : this.byId.get(category.parentCategoryId);
      const parentId = parent && parent.collectionId === category.collectionId && parent.workspaceId === category.workspaceId
        ? parent.categoryId : null;
      this.parents.set(category.categoryId, parentId);
      if (category.isSystem || (category.parentCategoryId !== null && parentId === null)) invalid.add(category.categoryId);
      if (parentId !== null) {
        const siblings = this.sourceChildren.get(parentId) ?? [];
        siblings.push(category.categoryId);
        this.sourceChildren.set(parentId, siblings);
      }
    }

    // Resolve each ancestry once. Break one edge per cycle for display; retain all edges for move validation.
    for (const category of this.byId.values()) {
      const path: number[] = [];
      const positions = new Map<number, number>();
      let current: number | null = category.categoryId;
      while (current !== null && !this.validAncestry.has(current) && !positions.has(current)) {
        positions.set(current, path.length);
        path.push(current);
        current = this.parents.get(current)!;
      }
      const cycleStart = current === null ? undefined : positions.get(current);
      if (cycleStart !== undefined) {
        let root = path[cycleStart];
        for (let index = cycleStart + 1; index < path.length; index++) root = Math.min(root, path[index]);
        this.parents.set(root, null);
      }
      let valid = current === null || this.validAncestry.get(current) === true;
      for (let index = path.length - 1; index >= 0; index--) {
        const id = path[index];
        valid = valid && !invalid.has(id);
        this.validAncestry.set(id, valid);
      }
    }

    for (const category of [...this.byId.values()].sort(compareCategories)) {
      const parentId = this.parents.get(category.categoryId)!;
      const siblings = this.children.get(parentId) ?? [];
      siblings.push(category);
      this.children.set(parentId, siblings);
    }
    const pending = this.childrenOf(null).map((category, rootIndex) => ({ category, rootIndex, depth: 0 })).reverse();
    while (pending.length > 0) {
      const row = pending.pop()!;
      const children = this.childrenOf(row.category.categoryId);
      this.rows.push({ ...row, hasChildren: children.length > 0 });
      this.rootIndices.set(row.category.categoryId, row.rootIndex);
      for (let index = children.length - 1; index >= 0; index--) {
        pending.push({ category: children[index], rootIndex: row.rootIndex, depth: row.depth + 1 });
      }
    }
  }

  childrenOf(id: number | null): Category[] {
    return this.children.get(id) ?? [];
  }

  pathTo(id: number | null): Category[] {
    const result: Category[] = [];
    let current = id === null ? undefined : this.byId.get(id);
    while (current) {
      result.push(current);
      const parent = this.parents.get(current.categoryId)!;
      current = parent === null ? undefined : this.byId.get(parent);
    }
    return result.reverse();
  }

  rootIndex(id: number): number {
    return this.rootIndices.get(id) ?? 0;
  }

  canBeParent(id: number): boolean {
    return this.validAncestry.get(id) === true;
  }

  descendantIds(id: number | null): Set<number> {
    const result = new Set<number>();
    if (id === null || !this.byId.has(id)) return result;
    const pending = [id];
    while (pending.length > 0) {
      const current = pending.pop()!;
      if (result.has(current)) continue;
      result.add(current);
      for (const child of this.sourceChildren.get(current) ?? []) pending.push(child);
    }
    return result;
  }
}
