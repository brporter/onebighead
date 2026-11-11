import { useEffect, useState, useCallback, useRef } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useCollectionsData, useCategoriesData, useItemsData, useSuggestionsData } from '../contexts/useData';
import { usePublish } from '../contexts/usePublish';
import CategoryNav from '../components/category/CategoryNav';
import { CategoryManagerModal } from '../components/category';
import { CategoryItems } from '../components/category/CategoryItems';
import { CollectionDashboard } from '../components/collection';
import { CollectionLayout } from '../components/collection/CollectionLayout';
import { CollectionHeader } from '../components/collection/CollectionHeader';
import { BackNav, PublishButton, PublicBadge } from '../components/common';
import { ContentState } from '../components/common/ContentState';
import { BulkUpdateStatus } from '../components/common/BulkUpdateStatus';
import { useCollectionBulkUpdate } from '../data/bulkUpdates/useCollectionBulkUpdate';
import { bulkUpdatesApi } from '../api/bulkUpdates';
import { parseRouteId } from '../utils/routeIds';
import { useCollectionRoute } from '../data/routes/useCollectionRoute';

function CategoryView() {
  const { collectionId, categoryId } = useParams<{ collectionId: string; categoryId?: string }>();
  const collection = parseRouteId(collectionId);
  const category = parseRouteId(categoryId);
  if (collection === null || (categoryId !== undefined && category === null)) {
    return <ContentState kind="error" title="Invalid collection link"
      action={<Link to="/collections">All Collections</Link>} />;
  }
  return <CollectionBrowser key={collection} collectionId={collection} categoryId={category} />;
}

function CollectionBrowser({ collectionId, categoryId }: { collectionId: number; categoryId: number | null }) {
  const navigate = useNavigate();
  const collectionsData = useCollectionsData();
  const categoriesData = useCategoriesData();
  const { items, itemsLoading, itemsError, loadItemsForCategory } = useItemsData();
  const { loadPropertySuggestions } = useSuggestionsData();
  const data = { ...collectionsData, ...categoriesData, loadPropertySuggestions };
  const { collections, collectionsLoading, collectionsError, loadCollections } = collectionsData;
  const { categoriesError, loadCategoriesForCollection } = categoriesData;
  const { collection, categories: collectionCategories, categoriesPending } = useCollectionRoute(collectionId, data);
  const { requestPublish, requestUnpublish } = usePublish();
  const [categoryManagerOpen, setCategoryManagerOpen] = useState(false);
  const resolvedCollectionId = collection?.collectionId;
  const itemRequest = useRef<AbortController | null>(null);

  const refreshItems = useCallback(() => {
    itemRequest.current?.abort();
    const controller = new AbortController();
    itemRequest.current = controller;
    if (categoryId !== null && resolvedCollectionId !== undefined) void loadItemsForCategory(categoryId, { signal: controller.signal });
  }, [categoryId, resolvedCollectionId, loadItemsForCategory]);
  useEffect(() => {
    refreshItems();
    return () => { itemRequest.current?.abort(); };
  }, [refreshItems]);
  const bulk = useCollectionBulkUpdate(resolvedCollectionId ?? null, bulkUpdatesApi, refreshItems);

  if (collectionsError) return <ContentState kind="error" title="Unable to load collections"
    action={<button type="button" onClick={() => void loadCollections()}>Try again</button>}>{collectionsError}</ContentState>;
  if (collectionsLoading) return <ContentState kind="loading" title="Loading..." />;
  if (!collection) return <ContentState kind="error" title="Collection not found"
    action={<Link to="/collections">All Collections</Link>}>This collection is unavailable in your current workspace.</ContentState>;

  const selectedCategory = collectionCategories.find(category => category.categoryId === categoryId);
  const homeHref = `/collections/${collectionId}`;
  const selectItem = (id: number) => navigate(`${homeHref}/items/${id}`);

  return <>
    <CollectionLayout
      sidebar={categoriesPending ? <ContentState kind="loading" title="Loading categories…" /> :
        <CategoryNav categories={collectionCategories} selectedCategoryId={categoryId}
          onSelect={id => navigate(id === null ? homeHref : `${homeHref}/categories/${id}`)}
          onEdit={() => setCategoryManagerOpen(true)} />}
      header={<CollectionHeader collection={collection} homeHref={categoryId === null ? undefined : homeHref}
        showAllCollections={collections.length > 1}
        actions={collection.effectiveIsPublic ?
          <PublicBadge effectiveIsPublic={collection.effectiveIsPublic}
            onUnpublish={() => requestUnpublish([{ type: 'collection', id: collectionId }])} /> :
          <PublishButton onPublish={() => requestPublish([{ type: 'collection', id: collectionId }])} />} />}>
      <BulkUpdateStatus job={bulk.job} error={bulk.error} onRetry={bulk.retry} />
      {categoriesError ? <ContentState kind="error" title="Unable to load categories"
        action={<button type="button" onClick={() => void loadCategoriesForCollection(collectionId)}>Try again</button>}>{categoriesError}</ContentState> :
        categoryId === null ? <CollectionDashboard collectionId={collectionId} onSelectItem={selectItem} /> :
          categoriesPending ? <ContentState kind="loading" title="Loading categories…" /> :
            !selectedCategory ? <ContentState kind="error" title="Category not found"
              action={<Link to={homeHref}>View collection</Link>} /> : <>
              <BackNav label="Categories" onClick={() => navigate(homeHref)} />
              <CategoryItems key={categoryId} categoryId={categoryId} categories={collectionCategories}
                items={items.filter(item => item.collectionId === collectionId)} loading={itemsLoading} error={itemsError}
                onRetry={refreshItems} onSelect={selectItem} onAdd={() => navigate(`${homeHref}/items/new?categoryId=${categoryId}`)} />
            </>}
    </CollectionLayout>
    <CategoryManagerModal collectionId={collectionId} isOpen={categoryManagerOpen} onClose={() => setCategoryManagerOpen(false)} />
  </>;
}

export default CategoryView;
