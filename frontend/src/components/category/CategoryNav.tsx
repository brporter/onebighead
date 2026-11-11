import { Fragment, useMemo } from 'react';
import type { Category } from '../../utils/types';
import { useCategoriesData, useItemsData } from '../../contexts/useData';
import { getAccentColor } from '../../utils/accentColors';
import { CategoryHierarchy } from '../../data/categories/CategoryHierarchy';
import './CategoryNav.css';

interface CategoryNavProps {
  categories: Category[];
  selectedCategoryId: number | null;
  onSelect: (categoryId: number | null) => void;
  onCollapse?: () => void;
  onEdit?: () => void;
}

function CategoryButton({ category, label, active, colorIndex, childCount, onSelect }: {
  category: Category; label: string; active: boolean; colorIndex: number; childCount: number;
  onSelect: (id: number) => void;
}) {
  return <button type="button" className={`categoryNav__row${active ? ' categoryNav__row--active' : ''}`}
    aria-current={active ? 'page' : undefined} onClick={() => onSelect(category.categoryId)}>
    <span className="categoryNav__dot" style={{ backgroundColor: getAccentColor(colorIndex).start }} aria-hidden="true" />
    <span className="categoryNav__rowContent">
      <span className="categoryNav__name">{label}</span>
      {childCount > 0 && <span className="categoryNav__count">({childCount})</span>}
    </span>
    {childCount > 0 && <span className="categoryNav__chevron" aria-hidden="true">&rsaquo;</span>}
  </button>;
}

function CategoryNav({ categories, selectedCategoryId, onSelect, onCollapse, onEdit }: CategoryNavProps) {
  const { categoriesLoading, categoriesError } = useCategoriesData();
  const { items } = useItemsData();
  const hierarchy = useMemo(() => {
    const occupied = new Set(items.map(item => item.categoryId));
    return new CategoryHierarchy(categories.filter(category => !category.isSystem || occupied.has(category.categoryId)));
  }, [categories, items]);
  const path = hierarchy.pathTo(selectedCategoryId);
  const selected = path.at(-1);
  const drillPath = selected && hierarchy.childrenOf(selected.categoryId).length === 0 && path.length > 1
    ? path.slice(0, -1) : path;
  const current = drillPath.at(-1);
  const displayed = hierarchy.childrenOf(current?.categoryId ?? null);
  const breadcrumb = [{ id: null as number | null, name: 'All' }, ...drillPath.map(category => ({ id: category.categoryId, name: category.name }))];

  if (categoriesError) return <aside className="categoryNav" aria-label="Categories">
    <h2 className="categoryNav__headerTitle">Categories</h2>
    <p className="categoryNav__error" role="alert">Error loading categories: {categoriesError}</p>
  </aside>;
  if (categoriesLoading) return <aside className="categoryNav" aria-label="Categories">
    <h2 className="categoryNav__headerTitle">Categories</h2>
    <p className="categoryNav__loading" role="status">Loading categories...</p>
  </aside>;

  return <aside className="categoryNav" aria-label="Categories">
    <div className="categoryNav__header">
      <h2 className="categoryNav__headerTitle">Categories</h2>
      <div className="categoryNav__headerActions">
        {onEdit && <button type="button" className="categoryNav__editBtn" onClick={onEdit} aria-label="Edit categories">&#9998;</button>}
        {onCollapse && <button type="button" className="categoryNav__collapseBtn" onClick={onCollapse} aria-label="Collapse categories">&laquo;</button>}
      </div>
    </div>
    {current && <nav className="categoryNav__breadcrumb" aria-label="Category breadcrumb">
      {breadcrumb.map((segment, index) => index === breadcrumb.length - 1
        ? <span key={segment.id} className="categoryNav__breadcrumb-current">{segment.name}</span>
        : <Fragment key={segment.id ?? 'all'}>
          <button type="button" className="categoryNav__breadcrumb-link" onClick={() => onSelect(segment.id)}
            aria-label={`Navigate to ${segment.name}`}>{segment.name}</button>
          <span className="categoryNav__breadcrumb-sep" aria-hidden="true">&rsaquo;</span>
        </Fragment>)}
    </nav>}
    <div className="categoryNav__list">
      {current && <>
        <button type="button" className="categoryNav__back" onClick={() => onSelect(drillPath.at(-2)?.categoryId ?? null)} aria-label="Go back">&larr; Back</button>
        <CategoryButton category={current} label={`All ${current.name}`} active={selectedCategoryId === current.categoryId}
          colorIndex={hierarchy.rootIndex(current.categoryId)} childCount={0} onSelect={onSelect} />
      </>}
      {displayed.map(category => <CategoryButton key={category.categoryId} category={category} label={category.name}
        active={category.categoryId === selectedCategoryId} colorIndex={hierarchy.rootIndex(category.categoryId)}
        childCount={hierarchy.childrenOf(category.categoryId).length} onSelect={onSelect} />)}
      {displayed.length === 0 && !current && <p className="categoryNav__empty">No categories yet</p>}
    </div>
  </aside>;
}

export { CategoryNav };
export default CategoryNav;
