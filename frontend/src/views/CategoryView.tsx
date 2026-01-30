import { useEffect, useMemo, useState } from 'react';
import { useParams, useNavigate, Outlet } from 'react-router-dom';
import { useData } from '../contexts/DataContext';
import CategoryTree from '../components/category/CategoryTree';
import ItemList from '../components/item/ItemList';
import SubcategoryDropdown from '../components/category/SubcategoryDropdown';
import BackNav from '../components/common/BackNav';
import { getCategoryAndDescendantIds } from '../utils/categoryUtils';

function CategoryView() {
  const { collectionId, categoryId } = useParams<{ collectionId: string; categoryId?: string }>();
  const navigate = useNavigate();
  const {
    collections,
    collectionsLoading,
    loadCollections,
    currentCollection,
    setCurrentCollection,
    categories,
    categoriesError,
    loadCategoriesForCollection,
    items,
    itemsLoading,
    itemsError,
    loadItemsForCategory,
    loadPropertySuggestions,
  } = useData();

  const [subcategoryFilter, setSubcategoryFilter] = useState<number | null>(null);
  const [pageIndex, setPageIndex] = useState(0);
  const [isLoading, setIsLoading] = useState(true);

  const collectionIdNum = collectionId ? parseInt(collectionId, 10) : null;
  const categoryIdNum = categoryId ? parseInt(categoryId, 10) : null;

  // Deep linking: Load collection data if needed
  useEffect(() => {
    if (!collectionsLoading && collections.length === 0) {
      loadCollections();
    }
  }, [collectionsLoading, collections.length, loadCollections]);

  // Set current collection once collections are loaded
  useEffect(() => {
    if (collectionIdNum && collections.length > 0 && currentCollection?.collectionId !== collectionIdNum) {
      const collection = collections.find(c => c.collectionId === collectionIdNum);
      if (collection) {
        setCurrentCollection(collection);
        loadCategoriesForCollection(collectionIdNum);
        loadPropertySuggestions(collectionIdNum);
      } else {
        // Collection not found, redirect to collections list
        navigate('/collections', { replace: true });
      }
    }
    setIsLoading(false);
  }, [collectionIdNum, collections, currentCollection, setCurrentCollection, loadCategoriesForCollection, loadPropertySuggestions, navigate]);

  // Load items when category changes
  useEffect(() => {
    if (categoryIdNum) {
      loadItemsForCategory(categoryIdNum);
      setSubcategoryFilter(null);
      setPageIndex(0);
    }
  }, [categoryIdNum, loadItemsForCategory]);

  const directSubcategories = useMemo(() => {
    if (categoryIdNum == null) return [];
    return categories.filter((cat) => cat.parentCategoryId === categoryIdNum);
  }, [categories, categoryIdNum]);

  const showSubcategoryDropdown = directSubcategories.length > 0;

  const eligibleCategoryIds = useMemo(() => {
    if (categoryIdNum == null) return new Set<number>();
    if (subcategoryFilter != null) {
      return getCategoryAndDescendantIds(categories, subcategoryFilter);
    }
    return getCategoryAndDescendantIds(categories, categoryIdNum);
  }, [categories, categoryIdNum, subcategoryFilter]);

  const filteredItems = useMemo(() => {
    if (categoryIdNum == null) return [];
    return items.filter((item) => item.categoryId !== null && eligibleCategoryIds.has(item.categoryId));
  }, [eligibleCategoryIds, items, categoryIdNum]);

  const totalPages = useMemo(() => {
    const pageSize = 25;
    return Math.max(1, Math.ceil(filteredItems.length / pageSize));
  }, [filteredItems.length]);

  const safePageIndex = useMemo(() => {
    return Math.min(Math.max(0, pageIndex), totalPages - 1);
  }, [pageIndex, totalPages]);

  function handleSelectCategory(catId: number) {
    navigate(`/collections/${collectionIdNum}/categories/${catId}`);
  }

  function handleSelectItem(itemId: number) {
    navigate(`/collections/${collectionIdNum}/items/${itemId}`);
  }

  function handleBackToCategories() {
    navigate(`/collections/${collectionIdNum}`);
  }

  function handleAddItem() {
    navigate(`/collections/${collectionIdNum}/items/new?categoryId=${categoryIdNum}`);
  }

  function handlePageChange(next: number) {
    const clamped = Math.min(Math.max(0, next), totalPages - 1);
    setPageIndex(clamped);
  }

  if (isLoading || collectionsLoading) {
    return <div className="app__loading">Loading...</div>;
  }

  if (!currentCollection) {
    return <div className="app__loading">Collection not found</div>;
  }

  // Show error state if categories or items failed to load
  if (categoriesError || itemsError) {
    return (
      <div className="app__layout">
        <main className="app__content">
          <div className="app__error">
            {categoriesError && <p>Failed to load categories: {categoriesError}</p>}
            {itemsError && <p>Failed to load items: {itemsError}</p>}
          </div>
        </main>
      </div>
    );
  }

  // Show category tree with placeholder if no category selected
  if (!categoryIdNum) {
    return (
      <div className="app__layout">
        <nav className="app__sidebar" aria-label="Category navigation">
          <CategoryTree
            categories={categories}
            selectedCategoryId={null}
            onSelect={handleSelectCategory}
          />
        </nav>
        <main className="app__content">
          <section className="placeholder">
            <p className="placeholder__text">Select a category to browse items</p>
          </section>
        </main>
      </div>
    );
  }

  // Show category tree with item list
  return (
    <div className="app__layout">
      <nav className="app__sidebar" aria-label="Category navigation">
        <CategoryTree
          categories={categories}
          selectedCategoryId={categoryIdNum}
          onSelect={handleSelectCategory}
        />
      </nav>
      <main className="app__content">
        <section className="app__items">
          <BackNav label="Categories" onClick={handleBackToCategories} />
          {showSubcategoryDropdown && (
            <SubcategoryDropdown
              subcategories={directSubcategories}
              selectedId={subcategoryFilter}
              onChange={setSubcategoryFilter}
            />
          )}
          {itemsLoading && filteredItems.length === 0 ? (
            <div className="app__loading">Loading items...</div>
          ) : (
            <ItemList
              items={filteredItems}
              selectedId={null}
              onSelect={handleSelectItem}
              onAddItem={handleAddItem}
              pageIndex={safePageIndex}
              onPageChange={handlePageChange}
            />
          )}
        </section>
      </main>
    </div>
  );
}

export default CategoryView;
