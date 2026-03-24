import { useEffect, useMemo, useState, useCallback, useRef } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useData } from '../contexts/useData';
import CategoryNav from '../components/category/CategoryNav';
import { CollectionDashboard } from '../components/collection';
import ItemList from '../components/item/ItemList';
import SubcategoryDropdown from '../components/category/SubcategoryDropdown';
import { BackNav, Loading } from '../components/common';
import { getCategoryAndDescendantIds } from '../utils/categoryUtils';
import { bulkUpdatesApi, type BulkUpdateJobResponse } from '../api';
import '../styles/components/BulkUpdateModal.css';

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

  const collectionIdNum = collectionId ? parseInt(collectionId, 10) : null;
  const categoryIdNum = categoryId ? parseInt(categoryId, 10) : null;

  const [sidebarCollapsed, setSidebarCollapsed] = useState(() =>
    typeof window !== 'undefined' && window.matchMedia('(max-width: 1024px)').matches
  );
  const [subcategoryFilter, setSubcategoryFilter] = useState<number | null>(null);
  const [pageIndex, setPageIndex] = useState(0);
  const [prevCategoryId, setPrevCategoryId] = useState(categoryIdNum);
  const [activeBulkJob, setActiveBulkJob] = useState<BulkUpdateJobResponse | null>(null);
  const bulkPollRef = useRef<number | null>(null);

  // Reset filters when category changes (setState during render pattern)
  if (categoryIdNum !== prevCategoryId) {
    setPrevCategoryId(categoryIdNum);
    setSubcategoryFilter(null);
    setPageIndex(0);
  }

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
        navigate('/collections', { replace: true });
      }
    }
  }, [collectionIdNum, collections, currentCollection, setCurrentCollection, loadCategoriesForCollection, loadPropertySuggestions, navigate]);

  // Load items when category changes
  useEffect(() => {
    if (categoryIdNum) {
      loadItemsForCategory(categoryIdNum);
    }
  }, [categoryIdNum, loadItemsForCategory]);

  // Check for active bulk update on collection load
  const checkBulkUpdate = useCallback(async (colId: number) => {
    try {
      const job = await bulkUpdatesApi.getCollectionStatus(colId);
      if (job && (job.status === 'Queued' || job.status === 'Running')) {
        setActiveBulkJob(job);
        // Start polling
        if (bulkPollRef.current) clearInterval(bulkPollRef.current);
        bulkPollRef.current = window.setInterval(async () => {
          try {
            const status = await bulkUpdatesApi.getStatus(job.jobId);
            setActiveBulkJob(status);
            if (status.status === 'Completed' || status.status === 'Failed') {
              if (bulkPollRef.current) clearInterval(bulkPollRef.current);
              bulkPollRef.current = null;
              // Refresh items after completion
              setTimeout(() => {
                setActiveBulkJob(null);
                if (categoryIdNum) loadItemsForCategory(categoryIdNum);
              }, 1500);
            }
          } catch {
            if (bulkPollRef.current) clearInterval(bulkPollRef.current);
            bulkPollRef.current = null;
            setActiveBulkJob(null);
          }
        }, 500);
      } else {
        setActiveBulkJob(null);
      }
    } catch {
      // Ignore errors
    }
  }, [categoryIdNum, loadItemsForCategory]);

  useEffect(() => {
    if (collectionIdNum && currentCollection) {
      void Promise.resolve().then(() => checkBulkUpdate(collectionIdNum));
    }
    return () => {
      if (bulkPollRef.current) {
        clearInterval(bulkPollRef.current);
        bulkPollRef.current = null;
      }
    };
  }, [collectionIdNum, currentCollection, checkBulkUpdate]);

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

  function handleSelectCategory(catId: number | null) {
    if (catId === null) {
      navigate(`/collections/${collectionIdNum}`);
    } else {
      navigate(`/collections/${collectionIdNum}/categories/${catId}`);
    }
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

  if (collectionsLoading || collections.length === 0) {
    return <Loading message="Loading..." />;
  }

  if (!currentCollection) {
    return <Loading message="Collection not found" />;
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

  function handleBackToCollections() {
    navigate('/collections');
  }

  const showBackToCollections = collections.length > 1;

  // Show category tree with placeholder if no category selected
  if (!categoryIdNum) {
    return (
      <div className={`app__layout${sidebarCollapsed ? ' app__layout--sidebar-collapsed' : ''}`}>
        <nav className="app__sidebar" aria-label="Category navigation">
          {sidebarCollapsed ? (
            <button
              type="button"
              className="app__sidebar-toggle"
              onClick={() => setSidebarCollapsed(false)}
              aria-label="Expand sidebar"
            >
              ▶
            </button>
          ) : (
            <CategoryNav
              categories={categories}
              selectedCategoryId={null}
              onSelect={handleSelectCategory}
              onCollapse={() => setSidebarCollapsed(true)}
            />
          )}
        </nav>
        <main className="app__content">
          <div className="collection-title-bar">
            {showBackToCollections && (
              <button className="collection-title-bar__back" onClick={handleBackToCollections}>
                ← All Collections
              </button>
            )}
            <h1 className="collection-title-bar__title">{currentCollection.name}</h1>
          </div>
          <CollectionDashboard
            collectionId={collectionIdNum!}
            onSelectItem={handleSelectItem}
          />
        </main>
      </div>
    );
  }

  // Show category tree with item list
  return (
    <div className={`app__layout${sidebarCollapsed ? ' app__layout--sidebar-collapsed' : ''}`}>
      <nav className="app__sidebar" aria-label="Category navigation">
        {sidebarCollapsed ? (
          <button
            type="button"
            className="app__sidebar-toggle"
            onClick={() => setSidebarCollapsed(false)}
            aria-label="Expand sidebar"
          >
            ▶
          </button>
        ) : (
          <CategoryNav
            categories={categories}
            selectedCategoryId={categoryIdNum}
            onSelect={handleSelectCategory}
            onCollapse={() => setSidebarCollapsed(true)}
          />
        )}
      </nav>
      <main className="app__content">
        <div className="collection-title-bar">
          {showBackToCollections && (
            <button className="collection-title-bar__back" onClick={handleBackToCollections}>
              ← All Collections
            </button>
          )}
          <Link to={`/collections/${collectionIdNum}`} className="collection-title-bar__title-link">
            <h1 className="collection-title-bar__title">{currentCollection.name}</h1>
          </Link>
          <p className="collection-title-bar__subtitle">Browse categories, then view items and details.</p>
        </div>
        <section className="app__items">
          <BackNav label="Categories" onClick={handleBackToCategories} />
          {activeBulkJob && (
            <div className="bulk-update-banner">
              <p className="bulk-update-banner__text">
                Updating item properties...
              </p>
              <div className="bulk-update-banner__bar-container">
                <div
                  className="bulk-update-banner__bar-fill"
                  style={{ width: `${activeBulkJob.totalItems > 0 ? Math.round(((activeBulkJob.processedItems + activeBulkJob.failedItems) / activeBulkJob.totalItems) * 100) : 0}%` }}
                />
              </div>
              <p className="bulk-update-banner__detail">
                {activeBulkJob.processedItems + activeBulkJob.failedItems} / {activeBulkJob.totalItems} items
                {activeBulkJob.status === 'Queued' && ' (queued)'}
              </p>
            </div>
          )}
          {showSubcategoryDropdown && (
            <SubcategoryDropdown
              subcategories={directSubcategories}
              selectedId={subcategoryFilter}
              onChange={setSubcategoryFilter}
            />
          )}
          {itemsLoading && filteredItems.length === 0 ? (
            <Loading message="Loading items..." />
          ) : (
            <ItemList
              items={filteredItems}
              categories={categories}
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
