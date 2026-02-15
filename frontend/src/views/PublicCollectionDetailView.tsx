import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { publicApi, type PublicCollectionDetail, type PublicItemSummary, type PublicCategory } from '../api';
import '../styles/components/PublicCollectionDetail.css';

function PublicCollectionDetailView() {
  const { slug, collectionId } = useParams<{ slug: string; collectionId: string }>();
  const navigate = useNavigate();
  const [detail, setDetail] = useState<PublicCollectionDetail | null>(null);
  const [items, setItems] = useState<PublicItemSummary[]>([]);
  const [selectedCategoryId, setSelectedCategoryId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [itemsLoading, setItemsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const collectionIdNum = collectionId ? parseInt(collectionId, 10) : null;

  useEffect(() => {
    if (!slug || !collectionIdNum) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- loading state must be set before async fetch
    setLoading(true);
    publicApi.getCollection(slug, collectionIdNum)
      .then(setDetail)
      .catch(() => setError('Collection not found'))
      .finally(() => setLoading(false));
  }, [slug, collectionIdNum]);

  useEffect(() => {
    if (!slug || !collectionIdNum) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- loading state must be set before async fetch
    setItemsLoading(true);
    publicApi.getItems(slug, collectionIdNum, selectedCategoryId ?? undefined)
      .then(setItems)
      .catch(() => setItems([]))
      .finally(() => setItemsLoading(false));
  }, [slug, collectionIdNum, selectedCategoryId]);

  if (loading) {
    return <div className="publicDetail__loading">Loading collection...</div>;
  }

  if (error || !detail) {
    return <div className="publicDetail__error">{error || 'Collection not found'}</div>;
  }

  const rootCategories = detail.categories.filter(c => !c.parentCategoryId);
  const childrenOf = (parentId: number) => detail.categories.filter(c => c.parentCategoryId === parentId);

  const renderCategory = (category: PublicCategory, depth: number = 0) => (
    <li key={category.id}>
      <button
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

  return (
    <div className="publicDetail">
      <div className="publicDetail__header">
        <button className="publicDetail__back" onClick={() => navigate(`/public/${slug}`)}>
          &larr; All Collections
        </button>
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
            <div className="publicDetail__loading">Loading items...</div>
          ) : items.length === 0 ? (
            <div className="publicDetail__empty">No items in this view.</div>
          ) : (
            <div className="publicDetail__itemGrid">
              {items.map(item => (
                <button
                  key={item.id}
                  className="publicDetail__itemCard"
                  onClick={() => navigate(`/public/${slug}/items/${item.id}`)}
                >
                  {item.primaryImageUrl && (
                    <div className="publicDetail__itemImageWrap">
                      <img src={item.primaryImageUrl} alt={item.name} className="publicDetail__itemImage" />
                    </div>
                  )}
                  <div className="publicDetail__itemContent">
                    <h3 className="publicDetail__itemName">{item.name}</h3>
                    {item.summary && <p className="publicDetail__itemSummary">{item.summary}</p>}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default PublicCollectionDetailView;
