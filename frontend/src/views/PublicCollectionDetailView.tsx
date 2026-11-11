import { useState, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { publicApi, type PublicItemSummary, type PublicCategory } from '../api';
import { useAsyncData } from '../utils/useAsyncData';
import { ContentState } from '../components/common/ContentState';
import { PublicCard } from '../components/public/PublicCard';
import { parseRouteId } from '../utils/routeIds';
import '../styles/components/PublicCollectionDetail.css';

function PublicCollectionDetailView() {
  const { slug, collectionId } = useParams<{ slug: string; collectionId: string }>();
  return <PublicCollectionContent key={`${slug}/${collectionId}`} slug={slug} collectionId={collectionId} />;
}

function PublicCollectionContent({ slug, collectionId }: { slug: string | undefined; collectionId: string | undefined }) {
  const [selectedCategoryId, setSelectedCategoryId] = useState<number | null>(null);

  const collectionIdNum = parseRouteId(collectionId);

  const fetchDetail = useCallback(
    (signal: AbortSignal) => publicApi.getCollection(slug!, collectionIdNum!, { signal }),
    [slug, collectionIdNum],
  );
  const { data: detail, loading, error } = useAsyncData(
    slug && collectionIdNum ? fetchDetail : null,
  );

  const fetchItems = useCallback(
    (signal: AbortSignal) => publicApi.getItems(slug!, collectionIdNum!, selectedCategoryId ?? undefined, { signal }),
    [slug, collectionIdNum, selectedCategoryId],
  );
  const { data: items, loading: itemsLoading, error: itemsError } = useAsyncData<PublicItemSummary[]>(
    slug && collectionIdNum ? fetchItems : null,
  );

  if (loading) {
    return <ContentState kind="loading" title="Loading collection…" />;
  }

  if (error || !detail) {
    return <ContentState kind="error" title="Collection unavailable">{error || 'Collection not found'}</ContentState>;
  }

  const rootCategories = detail.categories.filter(c => !c.parentCategoryId);
  const childrenOf = (parentId: number) => detail.categories.filter(c => c.parentCategoryId === parentId);

  const renderCategory = (category: PublicCategory, depth: number = 0) => (
    <li key={category.id}>
      <button
        type="button"
        aria-pressed={selectedCategoryId === category.id}
        className={`publicDetail__categoryBtn ${selectedCategoryId === category.id ? 'publicDetail__categoryBtn--active' : ''}`}
        style={{ paddingLeft: `${depth * 16 + 12}px` }}
        onClick={() => setSelectedCategoryId(selectedCategoryId === category.id ? null : category.id)}
      >
        {category.name}
      </button>
      {childrenOf(category.id).length > 0 && (
        <ul className="publicDetail__categoryList">
          {childrenOf(category.id).map(child => renderCategory(child, depth + 1))}
        </ul>
      )}
    </li>
  );

  const displayItems = items ?? [];

  return (
    <div className="publicDetail">
      <div className="publicDetail__header">
        <Link className="publicDetail__back" to={`/public/${slug}`}>
          &larr; All Collections
        </Link>
        <h1 className="publicDetail__title">{detail.collection.name}</h1>
        {detail.collection.description && (
          <p className="publicDetail__description">{detail.collection.description}</p>
        )}
      </div>
      <div className="publicDetail__content">
        {detail.categories.length > 0 && (
          <aside className="publicDetail__sidebar">
            <h2 className="publicDetail__sidebarTitle">Categories</h2>
            <button
              type="button"
              aria-pressed={selectedCategoryId === null}
              className={`publicDetail__categoryBtn ${selectedCategoryId === null ? 'publicDetail__categoryBtn--active' : ''}`}
              onClick={() => setSelectedCategoryId(null)}
            >
              All Items
            </button>
            <ul className="publicDetail__categoryList">
              {rootCategories.map(cat => renderCategory(cat))}
            </ul>
          </aside>
        )}
        <div className="publicDetail__items">
          {itemsLoading ? (
            <ContentState kind="loading" title="Loading items…" />
          ) : itemsError ? (
            <ContentState kind="error" title="Unable to load items">{itemsError}</ContentState>
          ) : displayItems.length === 0 ? (
            <ContentState kind="empty" title="No items in this view.">Try another category or browse all items.</ContentState>
          ) : (
            <div className="publicDetail__itemGrid">
              {displayItems.map(item => (
                <PublicCard key={item.id} to={`/public/${slug}/items/${item.id}`}
                  name={item.name} description={item.summary} imageUrl={item.primaryImageUrl} heading="h3" />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default PublicCollectionDetailView;
