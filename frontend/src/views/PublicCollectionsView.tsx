import { useCallback } from 'react';
import { useParams } from 'react-router-dom';
import { publicApi } from '../api';
import { useAsyncData } from '../utils/useAsyncData';
import { ContentState } from '../components/common/ContentState';
import { PublicCard } from '../components/public/PublicCard';
import '../styles/components/PublicCollections.css';

function PublicCollectionsView() {
  const { slug } = useParams<{ slug: string }>();

  const fetchCollections = useCallback(
    (signal: AbortSignal) => publicApi.getCollections(slug!, { signal }),
    [slug],
  );
  const { data: collections, loading, error } = useAsyncData(
    slug ? fetchCollections : null,
  );

  if (loading) {
    return <ContentState kind="loading" title="Loading collections…" />;
  }

  if (error) {
    return <ContentState kind="error" title="Unable to load collections">{error}</ContentState>;
  }

  if (!collections || collections.length === 0) {
    return (
      <ContentState kind="empty" title="No public collections available.">Published collections will appear here.</ContentState>
    );
  }

  return (
    <div className="publicCollections">
      <h1 className="publicCollections__title">Collections</h1>
      <div className="publicCollections__grid">
        {collections.map(collection => (
          <PublicCard key={collection.id} to={`/public/${slug}/collections/${collection.id}`}
            name={collection.name} description={collection.description} imageUrl={collection.heroImageUrl} heading="h2" />
        ))}
      </div>
    </div>
  );
}

export default PublicCollectionsView;
