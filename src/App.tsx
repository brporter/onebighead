import { useMemo, useState } from 'react';
import './styles/App.css';
import { useData } from './DataContext';
import BackNav from './BackNav';
import CategoryTree from './CategoryTree';
import ItemList from './ItemList';
import ItemDetail from './ItemDetail';
import SubcategoryDropdown from './SubcategoryDropdown';
import { getCategoryAndDescendantIds } from './categoryUtils';
import { createEmptyItem } from './itemUtils';
import type { Item } from './types';

type MobileView = 'categories' | 'items' | 'detail';
type ContentView = 'placeholder' | 'detail' | 'list';

function App() {
  const { categories, items, addItem, updateItem, deleteItem } = useData();

  const [selectedCategoryId, setSelectedCategoryId] = useState<number | null>(null);
  const [selectedItemId, setSelectedItemId] = useState<number | null>(null);
  const [pageIndex, setPageIndex] = useState(0);
  const [mobileView, setMobileView] = useState<MobileView>('categories');
  const [subcategoryFilter, setSubcategoryFilter] = useState<number | null>(null);
  const [isAddingItem, setIsAddingItem] = useState(false);

  const directSubcategories = useMemo(() => {
    if (selectedCategoryId == null) return [];
    return categories.filter((cat) => cat.parentCategoryId === selectedCategoryId);
  }, [categories, selectedCategoryId]);

  const showSubcategoryDropdown = directSubcategories.length > 0;

  const eligibleCategoryIds = useMemo(() => {
    if (selectedCategoryId == null) return new Set<number>();
    if (subcategoryFilter != null) {
      return getCategoryAndDescendantIds(categories, subcategoryFilter);
    }
    return getCategoryAndDescendantIds(categories, selectedCategoryId);
  }, [categories, selectedCategoryId, subcategoryFilter]);

  const filteredItems = useMemo(() => {
    if (selectedCategoryId == null) return [];
    return items.filter((item) => item.categoryId !== null && eligibleCategoryIds.has(item.categoryId));
  }, [eligibleCategoryIds, items, selectedCategoryId]);

  const totalPages = useMemo(() => {
    const pageSize = 25;
    return Math.max(1, Math.ceil(filteredItems.length / pageSize));
  }, [filteredItems.length]);

  const safePageIndex = useMemo(() => {
    return Math.min(Math.max(0, pageIndex), totalPages - 1);
  }, [pageIndex, totalPages]);

  const selectedItem = useMemo(() => {
    if (selectedItemId == null) return null;
    return items.find((item) => item.id === selectedItemId) ?? null;
  }, [items, selectedItemId]);

  const newItemTemplate = useMemo(() => {
    if (!isAddingItem || selectedCategoryId == null) return null;
    return createEmptyItem(selectedCategoryId, 1);
  }, [isAddingItem, selectedCategoryId]);

  const contentView: ContentView = useMemo(() => {
    if (selectedCategoryId == null) return 'placeholder';
    if (isAddingItem || selectedItem) return 'detail';
    return 'list';
  }, [selectedCategoryId, isAddingItem, selectedItem]);

  const detailItem = isAddingItem ? newItemTemplate : selectedItem;

  function handleSelectCategory(categoryId: number) {
    setSelectedCategoryId(categoryId);
    setSelectedItemId(null);
    setPageIndex(0);
    setSubcategoryFilter(null);
    setMobileView('items');
  }

  function handleSelectItem(itemId: number) {
    setSelectedItemId(itemId);
    setMobileView('detail');
  }

  function handleBackToCategories() {
    setMobileView('categories');
  }

  function handleBackToItems() {
    setSelectedItemId(null);
    setIsAddingItem(false);
    setMobileView('items');
  }

  function handlePageChange(next: number) {
    const clamped = Math.min(Math.max(0, next), totalPages - 1);
    setPageIndex(clamped);
  }

  function handleAddItem() {
    setIsAddingItem(true);
    setSelectedItemId(null);
    setMobileView('detail');
  }

  function handleSaveItem(itemData: Item) {
    if (isAddingItem) {
      addItem(itemData);
      setIsAddingItem(false);
      setMobileView('items');
    } else if (selectedItemId != null) {
      updateItem(selectedItemId, itemData);
    }
  }

  function handleDeleteItem(id: number) {
    deleteItem(id);
    setSelectedItemId(null);
    setMobileView('items');
  }

  function renderContent() {
    switch (contentView) {
      case 'placeholder':
        return (
          <section className="placeholder">
            <p className="placeholder__text">Select a category to browse items</p>
          </section>
        );

      case 'detail':
        return (
          <article className="app__detail">
            <BackNav label="Back to items" onClick={handleBackToItems} />
            <ItemDetail
              item={detailItem}
              isNew={isAddingItem}
              onClose={handleBackToItems}
              onSave={handleSaveItem}
              onDelete={isAddingItem ? undefined : handleDeleteItem}
            />
          </article>
        );

      case 'list':
        return (
          <section className="app__items">
            <BackNav label="Categories" onClick={handleBackToCategories} />
            {showSubcategoryDropdown && (
              <SubcategoryDropdown
                subcategories={directSubcategories}
                selectedId={subcategoryFilter}
                onChange={setSubcategoryFilter}
              />
            )}
            <ItemList
              items={filteredItems}
              selectedId={null}
              onSelect={handleSelectItem}
              onAddItem={handleAddItem}
              pageIndex={safePageIndex}
              onPageChange={handlePageChange}
            />
          </section>
        );
    }
  }

  return (
    <div className="app" data-mobile-view={mobileView}>
      <header className="app__header">
        <h1>Vintage Macintosh Models</h1>
        <p className="app__subtitle">Browse categories, then view items and details.</p>
      </header>

      <div className="app__layout">
        <nav className="app__sidebar" aria-label="Category navigation">
          <CategoryTree
            categories={categories}
            selectedCategoryId={selectedCategoryId}
            onSelect={handleSelectCategory}
          />
        </nav>

        <main className="app__content">
          {renderContent()}
        </main>
      </div>
    </div>
  );
}

export default App;

