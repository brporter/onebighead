import { useMemo, useState } from 'react';
import type { Category, Item } from '../../utils/types';
import { CategoryHierarchy } from '../../data/categories/CategoryHierarchy';
import { ContentState } from '../common/ContentState';
import ItemList from '../item/ItemList';
import SubcategoryDropdown from './SubcategoryDropdown';

interface CategoryItemsProps {
  categoryId: number;
  categories: Category[];
  items: Item[];
  loading: boolean;
  error: string | null;
  onRetry: () => void;
  onSelect: (id: number) => void;
  onAdd: () => void;
}

/** Mount with the category ID as a key so filters and selections reset together. */
export function CategoryItems({ categoryId, categories, items, loading, error, onRetry, onSelect, onAdd }: CategoryItemsProps) {
  const [subcategory, setSubcategory] = useState<number | null>(null);
  const [pageIndex, setPageIndex] = useState(0);
  const hierarchy = useMemo(() => new CategoryHierarchy(categories), [categories]);
  const children = hierarchy.childrenOf(categoryId);
  const selectedSubcategory = children.some(category => category.categoryId === subcategory) ? subcategory : null;
  const filteredItems = useMemo(() => {
    const root = hierarchy.byId.get(categoryId);
    const eligibleIds = hierarchy.descendantIds(selectedSubcategory ?? categoryId);
    return items.filter(item => root && item.workspaceId === root.workspaceId && item.collectionId === root.collectionId &&
      item.categoryId !== null && eligibleIds.has(item.categoryId));
  }, [hierarchy, categoryId, selectedSubcategory, items]);

  if (error) return <ContentState kind="error" title="Unable to load items"
    action={<button type="button" onClick={onRetry}>Try again</button>}>{error}</ContentState>;
  if (loading && filteredItems.length === 0) return <ContentState kind="loading" title="Loading items…" />;

  return <section className="collection-layout__items" aria-label="Category items" aria-busy={loading}>
    <SubcategoryDropdown subcategories={children} selectedId={selectedSubcategory} onChange={id => {
      setSubcategory(id);
      setPageIndex(0);
    }} />
    <ItemList items={filteredItems} categories={categories} selectedId={null}
      onSelect={onSelect} onAddItem={onAdd} pageIndex={pageIndex} onPageChange={setPageIndex} />
  </section>;
}
