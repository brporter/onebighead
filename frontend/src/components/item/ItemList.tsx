import { useState, useCallback } from 'react';
import type { Item, Category } from '../../utils/types';
import ItemCard from './ItemCard';
import { getAccentColor } from '../../utils/accentColors';
import { VisibilityFilter, BulkActionBar } from '../common';
import type { VisibilityFilterValue } from '../common';
import { useData } from '../../contexts/useData';
import { useToast } from '../../contexts/useToast';
import { buildBulkPublishToastMessage, buildBulkPublishToastDetails, buildBulkUnpublishToastMessage } from '../../utils/publishToastUtils';

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
  const { bulkPublishItems, bulkUnpublishItems } = useData();
  const { showToast } = useToast();
  const [filterValue, setFilterValue] = useState<VisibilityFilterValue>('all');
  const [selectedItems, setSelectedItems] = useState<Set<number>>(new Set());
  const [selectionMode, setSelectionMode] = useState(false);

  // Filter items based on visibility
  const filteredItems = items.filter((item) => {
    if (filterValue === 'all') return true;
    if (filterValue === 'public') return item.effectiveIsPublic;
    return !item.effectiveIsPublic;
  });

  const totalCount = items.length;
  const filteredCount = filteredItems.length;
  const totalPages = Math.max(1, Math.ceil(filteredCount / PAGE_SIZE));
  const safePageIndex = Math.min(Math.max(0, pageIndex), totalPages - 1);
  const start = safePageIndex * PAGE_SIZE;
  const pageItems = filteredItems.slice(start, start + PAGE_SIZE);

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

  const handleToggleCheck = useCallback((id: number) => {
    setSelectedItems((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  const handleCancelSelection = useCallback(() => {
    setSelectionMode(false);
    setSelectedItems(new Set());
  }, []);

  async function handleBulkPublish() {
    const ids = Array.from(selectedItems);
    const result = await bulkPublishItems(ids);
    showToast(buildBulkPublishToastMessage(result), buildBulkPublishToastDetails(result));
    handleCancelSelection();
  }

  async function handleBulkUnpublish() {
    const ids = Array.from(selectedItems);
    const result = await bulkUnpublishItems(ids);
    showToast(buildBulkUnpublishToastMessage(result));
    handleCancelSelection();
  }

  function handleFilterChange(value: VisibilityFilterValue) {
    setFilterValue(value);
    onPageChange(0);
  }

  return (
    <aside className="list">
      <div className="list__header">
        <h2 className="list__title">Items</h2>
        <div className="list__headerRight">
          <div className="list__count" aria-label="Item count">
            {totalCount} total
          </div>
          {!selectionMode && (
            <button
              type="button"
              className="list__selectButton"
              onClick={() => setSelectionMode(true)}
            >
              Select
            </button>
          )}
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

      <VisibilityFilter
        value={filterValue}
        onChange={handleFilterChange}
        totalCount={totalCount}
        filteredCount={filteredCount}
      />

      {selectionMode && (
        <BulkActionBar
          selectedCount={selectedItems.size}
          onPublish={handleBulkPublish}
          onUnpublish={handleBulkUnpublish}
          onCancel={handleCancelSelection}
        />
      )}

      <div className="list__masonry">
        {pageItems.length ? (
          pageItems.map((item, index) => (
            <ItemCard
              key={item.id ?? `new-${index}-${item.name}`}
              item={item}
              accentColor={getItemAccentColor(item)}
              isSelected={item.id === selectedId}
              onSelect={onSelect}
              selectionMode={selectionMode}
              isChecked={item.id !== null ? selectedItems.has(item.id) : false}
              onToggleCheck={handleToggleCheck}
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
