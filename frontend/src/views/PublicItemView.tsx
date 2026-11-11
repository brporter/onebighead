import { useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { publicApi } from '../api';
import { useAsyncData } from '../utils/useAsyncData';
import { ContentState } from '../components/common/ContentState';
import PropertyRender from '../components/item/PropertyRender';
import ImageGallery from '../components/common/ImageGallery';
import { parseRouteId } from '../utils/routeIds';
import '../styles/components/PublicItem.css';

function PublicItemView() {
  const { slug, itemId } = useParams<{ slug: string; itemId: string }>();

  const itemIdNum = parseRouteId(itemId);

  const fetchItem = useCallback(
    (signal: AbortSignal) => publicApi.getItem(slug!, itemIdNum!, { signal }),
    [slug, itemIdNum],
  );
  const { data: item, loading, error } = useAsyncData(
    slug && itemIdNum ? fetchItem : null,
  );

  if (loading) {
    return <ContentState kind="loading" title="Loading item…" />;
  }

  if (error || !item) {
    return <ContentState kind="error" title="Item unavailable">{error || 'Item not found'}</ContentState>;
  }

  return (
    <div className="publicItem">
      <Link className="publicItem__back" to={`/public/${slug}`}>
        &larr; All Collections
      </Link>
      <div className="publicItem__layout">
        {item.images.length > 0 && (
          <div className="publicItem__gallery">
            <ImageGallery key={item.id} images={item.images} title={item.name} />
          </div>
        )}
        <div className="publicItem__info">
          <h1 className="publicItem__name">{item.name}</h1>
          {item.categoryName && <div className="publicItem__category">{item.categoryName}</div>}
          {item.summary && <p className="publicItem__summary">{item.summary}</p>}
          {item.description && <div className="publicItem__description">{item.description}</div>}
          <PropertyRender properties={item.properties} heading="h2" />
        </div>
      </div>
    </div>
  );
}

export default PublicItemView;
