import { useState } from 'react';
import { useParams, useNavigate, useSearchParams, Link } from 'react-router-dom';
import { useCollectionsData, useCategoriesData, useItemsData, useSuggestionsData } from '../contexts/useData';
import type { CollectionsData, CategoriesData, ItemsData, SuggestionsData } from '../contexts/dataContexts';
import ItemDetail from '../components/item/ItemDetail';
import ItemEditor from '../components/item/ItemEditor';
import { BackNav, BulkUpdateModal, ContentState } from '../components/common';
import { CollectionHeader, CollectionLayout } from '../components/collection';
import CategoryNav from '../components/category/CategoryNav';
import TemplateSelector from '../components/template/TemplateSelector';
import { bulkUpdatesApi } from '../api/bulkUpdates';
import { itemsApi } from '../api/items';
import { useCollectionRoute } from '../data/routes/useCollectionRoute';
import { useItemDetails } from '../data/items/useItemDetails';
import { useItemWorkflow } from '../data/items/useItemWorkflow';
import { createEmptyItem } from '../utils/itemUtils';
import { parseRouteId } from '../utils/routeIds';
import { useUnsavedNavigation } from '../data/shared/useUnsavedNavigation';
import type { Category, Collection, Item, ItemProperty } from '../utils/types';

function parentPath(collectionId: number, categoryId: number | null) {
  const home = `/collections/${collectionId}`;
  return categoryId === null ? home : `${home}/categories/${categoryId}`;
}

function ItemView() {
  const params = useParams<{ collectionId: string; itemId: string }>();
  const [search] = useSearchParams();
  const collectionId = parseRouteId(params.collectionId);
  const itemId = params.itemId === 'new' ? 'new' : parseRouteId(params.itemId);
  const categoryQuery = itemId === 'new' ? search.get('categoryId') : null;
  const categoryId = parseRouteId(categoryQuery ?? undefined);
  if (collectionId === null || itemId === null || (categoryQuery !== null && categoryId === null)) {
    return <ContentState kind="error" title="Invalid item link" action={<Link to="/collections">All Collections</Link>} />;
  }
  return <ItemRoute key={`${collectionId}/${itemId}/${categoryId}`} collectionId={collectionId} itemId={itemId} categoryId={categoryId} />;
}

function ItemRoute({ collectionId, itemId, categoryId }: { collectionId: number; itemId: number | 'new'; categoryId: number | null }) {
  const collectionsData = useCollectionsData();
  const categoriesData = useCategoriesData();
  const itemsData = useItemsData();
  const { loadPropertySuggestions } = useSuggestionsData();
  const data = { ...collectionsData, ...categoriesData, ...itemsData, loadPropertySuggestions };
  const { collection, categories, categoriesPending } = useCollectionRoute(collectionId, data);
  if (data.collectionsError) return <ContentState kind="error" title="Unable to load collections"
    action={<button type="button" onClick={() => void data.loadCollections()}>Try again</button>}>{data.collectionsError}</ContentState>;
  if (data.collectionsLoading) return <ContentState kind="loading" title="Loading..." />;
  if (!collection) return <ContentState kind="error" title="Collection not found"
    action={<Link to="/collections">All Collections</Link>} />;
  if (data.categoriesError) return <ContentState kind="error" title="Unable to load categories"
    action={<button type="button" onClick={() => void data.loadCategoriesForCollection(collectionId)}>Try again</button>}>{data.categoriesError}</ContentState>;
  const page = { collection, categories, categoriesPending, data };
  return itemId === 'new' ? <NewItem categoryId={categoryId} {...page} /> : <ExistingItem itemId={itemId} {...page} />;
}

interface ItemPageProps {
  collection: Collection;
  categories: Category[];
  categoriesPending: boolean;
  data: CollectionsData & CategoriesData & ItemsData & Pick<SuggestionsData, 'loadPropertySuggestions'>;
}

function ExistingItem({ itemId, ...page }: ItemPageProps & { itemId: number }) {
  const details = useItemDetails(page.collection.collectionId, itemId, page.data, itemsApi.recordView);
  // This route owner outlives a disappearing detail while deletion finishes navigating.
  const workflow = useItemPageWorkflow(details.item, page);
  if (details.loading) return <ContentState kind="loading" title="Loading item…" />;
  if (details.error) return <ContentState kind="error" title="Unable to load item"
    action={<button type="button" onClick={details.retry}>Try again</button>}>{details.error}</ContentState>;
  if (!details.item) return <ContentState kind="error" title="Item not found"
    action={<Link to={`/collections/${page.collection.collectionId}`}>View collection</Link>} />;
  return <ItemPage workflow={workflow} {...page} />;
}

function NewItem({ categoryId, ...page }: ItemPageProps & { categoryId: number | null }) {
  const navigate = useNavigate();
  const [selection, setSelection] = useState<{ properties: ItemProperty[]; templateKey: string | null } | null>(null);
  const home = `/collections/${page.collection.collectionId}`;
  if (page.categoriesPending) return <ContentState kind="loading" title="Loading categories…" />;
  if (categoryId !== null && !page.categories.some(category => category.categoryId === categoryId)) {
    return <ContentState kind="error" title="Category not found" action={<Link to={home}>View collection</Link>} />;
  }
  if (selection === null) return <TemplateSelector collectionId={page.collection.collectionId} categoryId={categoryId}
    isOpen onClose={() => navigate(parentPath(page.collection.collectionId, categoryId))} onSelect={setSelection} />;
  const item = { ...createEmptyItem(categoryId, page.collection.collectionId, page.collection.workspaceId, selection.templateKey),
    properties: selection.properties };
  return <NewItemSession item={item} {...page} />;
}

function useItemPageWorkflow(item: Item | null, { collection, categories, data }: ItemPageProps) {
  const navigate = useNavigate();
  const [status, reportStatus] = useState({ dirty: false, pending: false });
  const completeNavigation = useUnsavedNavigation(status.dirty, status.pending);
  const leave = (value: Item) => completeNavigation(() => { void navigate(parentPath(collection.collectionId, value.categoryId)); });
  const workflow = useItemWorkflow(item, categories, data, bulkUpdatesApi, leave);
  return { ...workflow, reportStatus };
}

function NewItemSession({ item, ...page }: ItemPageProps & { item: Item }) {
  const workflow = useItemPageWorkflow(item, page);
  return <ItemPage workflow={workflow} {...page} />;
}

function ItemPage({ workflow, collection, categories, categoriesPending, data }: ItemPageProps & { workflow: ReturnType<typeof useItemPageWorkflow> }) {
  const navigate = useNavigate();
  const home = `/collections/${collection.collectionId}`;
  const item = workflow.item!;
  const back = () => navigate(parentPath(collection.collectionId, item.categoryId));
  return <CollectionLayout
    header={<CollectionHeader collection={collection} homeHref={home} showAllCollections={data.collections.length > 1} />}
    sidebar={categoriesPending ? <ContentState kind="loading" title="Loading categories…" /> :
      <CategoryNav categories={categories} selectedCategoryId={item.categoryId}
        onSelect={id => navigate(parentPath(collection.collectionId, id))} />}>
    <article className="app__detail">
      <BackNav label="Back to items" onClick={back} />
      {workflow.editing ? <ItemEditor item={item} categories={categories} collection={collection}
        onStatusChange={workflow.reportStatus}
        onSave={workflow.save} onCancel={workflow.cancelEdit} onDelete={item.id === null ? undefined : workflow.remove} /> :
        <ItemDetail item={item} onEdit={workflow.beginEdit} onClose={back} />}
      {workflow.previewIssue && <ContentState kind="error" title="Item saved; related items could not be checked"
        action={<button type="button" onClick={workflow.previewIssue.retry}>Try again</button>}>{workflow.previewIssue.message}</ContentState>}
    </article>
    {workflow.offer && <BulkUpdateModal isOpen onClose={workflow.closeOffer} onComplete={workflow.completeBulkUpdate} {...workflow.offer} />}
  </CollectionLayout>;
}

export default ItemView;
