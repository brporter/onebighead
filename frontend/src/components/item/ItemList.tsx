import type { Item, Category } from '../../utils/types';
import ItemCard from './ItemCard';
import { getAccentColor } from '../../utils/accentColors';

const PAGE_SIZE = 25;

interface ItemListProps {
  items: Item[];
  categories: Category[];
  selectedId: number | null;
  onSelect: (id: number) => void;
  onAddItem?: (() => void) | null;
  pageIndex: number;
  onPageChange: (pageIndex: number) => void;
}

function ItemList({ items, categories, selectedId, onSelect, onAddItem, pageIndex, onPageChange }: ItemListProps) {
  const totalCount = items.length;
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
  const safePageIndex = Math.min(Math.max(0, pageIndex), totalPages - 1);
  const start = safePageIndex * PAGE_SIZE;
  const pageItems = items.slice(start, start + PAGE_SIZE);

  const canPrev = safePageIndex > 0;
  const canNext = safePageIndex < totalPages - 1;

  // Build category index map for accent colors
  const categoryColorIndex = new Map<number, number>();
  categories.forEach((cat, index) => {
    categoryColorIndex.set(cat.categoryId, index);
  });

  function getItemAccentColor(item: Item) {
    const catIndex = item.categoryId !== null ? (categoryColorIndex.get(item.categoryId) ?? 0) : 0;
    return getAccentColor(catIndex);
  }

  return (
    <aside className="list">
      <div className="list__header">
        <h2 className="list__title">Items</h2>
        <div className="list__headerRight">
          <div className="list__count" aria-label="Item count">
            {totalCount} total
          </div>
          {onAddItem && (
            <button
              type="button"
              className="list__addButton"
              onClick={onAddItem}
            >
              + Add Item
            </button>
          )}
        </div>
      </div>

      <div className="list__masonry">
        {pageItems.length ? (
          pageItems.map((item, index) => (
            <ItemCard
              key={item.id ?? `new-${index}-${item.name}`}
              item={item}
              accentColor={getItemAccentColor(item)}
              isSelected={item.id === selectedId}
              onSelect={onSelect}
            />
          ))
        ) : (
          <p className="list__empty">No items</p>
        )}
      </div>

      <div className="list__pager" aria-label="Pagination">
        <button
          type="button"
          className="list__pagerButton"
          onClick={() => onPageChange(safePageIndex - 1)}
          disabled={!canPrev}
        >
          Previous
        </button>
        <div className="list__pagerStatus">
          Page {safePageIndex + 1} of {totalPages}
        </div>
        <button
          type="button"
          className="list__pagerButton"
          onClick={() => onPageChange(safePageIndex + 1)}
          disabled={!canNext}
        >
          Next
        </button>
      </div>
    </aside>
  );
}

export default ItemList;
