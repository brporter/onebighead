import { useMemo, useState } from 'react';
import type { Category, CategoryNode } from './types';
import { useData } from './DataContext';
import CategoryEditorModal from './CategoryEditorModal';

interface CategoryNodeProps {
  node: CategoryNode;
  level: number;
  selectedCategoryId: number | null;
  onSelect: (categoryId: number) => void;
  expandedIds: Set<number>;
  onToggle: (categoryId: number) => void;
  onEdit: (category: Category) => void;
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

function CategoryNodeComponent({ node, level, selectedCategoryId, onSelect, expandedIds, onToggle, onEdit }: CategoryNodeProps) {
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
          className={`categoryTree__item${isSelected ? ' categoryTree__item--active' : ''}${node.isSystem ? ' categoryTree__item--system' : ''}`}
          onClick={() => onSelect(node.categoryId)}
        >
          {node.name}
        </button>

        {!node.isSystem && (
          <button
            type="button"
            className="categoryTree__edit"
            aria-label={`Edit ${node.name}`}
            onClick={(e) => {
              e.stopPropagation();
              onEdit(node);
            }}
          >
            ✎
          </button>
        )}
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
              onEdit={onEdit}
            />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function CategoryTree({ categories, selectedCategoryId, onSelect }: CategoryTreeProps) {
  const { categoriesLoading, categoriesError, items, loadCategoriesForCollection, loadItemsForCategory, currentCollection } = useData();
  const [modalOpen, setModalOpen] = useState(false);
  const [editingCategory, setEditingCategory] = useState<Category | null>(null);

  // Filter out system categories that have no items
  const visibleCategories = useMemo(() => {
    const itemCategoryIds = new Set(items.map((item) => item.categoryId).filter((id): id is number => id !== null));
    return categories.filter((cat) => {
      if (!cat.isSystem) return true;
      // Show system categories only if they contain items
      return itemCategoryIds.has(cat.categoryId);
    });
  }, [categories, items]);

  const tree = useMemo(() => buildTree(visibleCategories), [visibleCategories]);
  
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

  function handleEdit(category: Category) {
    setEditingCategory(category);
    setModalOpen(true);
  }

  function handleAddNew() {
    setEditingCategory(null);
    setModalOpen(true);
  }

  function handleModalClose() {
    setModalOpen(false);
    setEditingCategory(null);
  }

  async function handleModalSaved() {
    // Reload categories and items for current collection
    if (currentCollection) {
      await loadCategoriesForCollection(currentCollection.collectionId);
      if (selectedCategoryId) {
        await loadItemsForCategory(selectedCategoryId);
      }
    }
  }

  if (categoriesError) {
    return (
      <aside className="categoryTree">
        <h2 className="categoryTree__title">Categories</h2>
        <p className="categoryTree__error" role="alert">Error loading categories: {categoriesError}</p>
      </aside>
    );
  }

  if (categoriesLoading) {
    return (
      <aside className="categoryTree">
        <h2 className="categoryTree__title">Categories</h2>
        <p className="categoryTree__loading">Loading categories...</p>
      </aside>
    );
  }

  return (
    <aside className="categoryTree">
      <div className="categoryTree__header">
        <h2 className="categoryTree__title">Categories</h2>
        <button
          type="button"
          className="categoryTree__add"
          onClick={handleAddNew}
          aria-label="Add category"
        >
          +
        </button>
      </div>
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
            onEdit={handleEdit}
          />
        ))}
      </ul>

      <CategoryEditorModal
        category={editingCategory}
        isOpen={modalOpen}
        onClose={handleModalClose}
        onSaved={handleModalSaved}
      />
    </aside>
  );
}

export { CategoryTree };
export default CategoryTree;

