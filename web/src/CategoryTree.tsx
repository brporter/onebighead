import { useMemo, useState } from 'react';
import type { Category, CategoryNode } from './types';

interface CategoryNodeProps {
  node: CategoryNode;
  level: number;
  selectedCategoryId: number | null;
  onSelect: (categoryId: number) => void;
  expandedIds: Set<number>;
  onToggle: (categoryId: number) => void;
}

interface CategoryTreeProps {
  categories: Category[];
  selectedCategoryId: number | null;
  onSelect: (categoryId: number) => void;
}

function buildTree(categories: Category[]): CategoryNode[] {
  const byId = new Map<number, CategoryNode>();
  const roots: CategoryNode[] = [];

  for (const cat of categories ?? []) {
    byId.set(cat.categoryId, { ...cat, children: [] });
  }

  for (const node of byId.values()) {
    if (node.parentCategoryId == null) {
      roots.push(node);
      continue;
    }

    const parent = byId.get(node.parentCategoryId);
    if (parent) parent.children.push(node);
    else roots.push(node);
  }

  return roots;
}

function CategoryNodeComponent({ node, level, selectedCategoryId, onSelect, expandedIds, onToggle }: CategoryNodeProps) {
  const isSelected = node.categoryId === selectedCategoryId;
  const hasChildren = node.children.length > 0;
  const isExpanded = expandedIds.has(node.categoryId);

  return (
    <li className="categoryTree__node">
      <div className="categoryTree__row" style={{ paddingLeft: `${level * 14}px` }}>
        {hasChildren ? (
          <button
            type="button"
            className="categoryTree__toggle"
            aria-label={isExpanded ? `Collapse ${node.name}` : `Expand ${node.name}`}
            onClick={() => onToggle(node.categoryId)}
          >
            {isExpanded ? '▾' : '▸'}
          </button>
        ) : (
          <span className="categoryTree__toggle-spacer" aria-hidden="true">
            ▸
          </span>
        )}

        <button
          type="button"
          className={`categoryTree__item${isSelected ? ' categoryTree__item--active' : ''}`}
          onClick={() => onSelect(node.categoryId)}
        >
          {node.name}
        </button>
      </div>

      {hasChildren && isExpanded ? (
        <ul className="categoryTree__children">
          {node.children.map((child) => (
            <CategoryNodeComponent
              key={child.categoryId}
              node={child}
              level={level + 1}
              selectedCategoryId={selectedCategoryId}
              onSelect={onSelect}
              expandedIds={expandedIds}
              onToggle={onToggle}
            />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function CategoryTree({ categories, selectedCategoryId, onSelect }: CategoryTreeProps) {
  const tree = useMemo(() => buildTree(categories), [categories]);
  const [expandedIds, setExpandedIds] = useState<Set<number>>(() => {
    const rootIds = (categories ?? [])
      .filter((c) => c.parentCategoryId == null)
      .map((c) => c.categoryId);
    return new Set(rootIds);
  });

  function toggle(id: number) {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <aside className="categoryTree">
      <h2 className="categoryTree__title">Categories</h2>
      <ul className="categoryTree__list">
        {tree.map((node) => (
          <CategoryNodeComponent
            key={node.categoryId}
            node={node}
            level={0}
            selectedCategoryId={selectedCategoryId}
            onSelect={onSelect}
            expandedIds={expandedIds}
            onToggle={toggle}
          />
        ))}
      </ul>
    </aside>
  );
}

export { CategoryTree };
export default CategoryTree;

