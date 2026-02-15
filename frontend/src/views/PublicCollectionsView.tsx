import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { publicApi, type PublicCollection } from '../api';
import '../styles/components/PublicCollections.css';

function PublicCollectionsView() {
  const { slug } = useParams<{ slug: string }>();
  const navigate = useNavigate();
  const [collections, setCollections] = useState<PublicCollection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!slug) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- loading state must be set before async fetch
    setLoading(true);
    publicApi.getCollections(slug)
      .then(setCollections)
      .catch(() => setError('Failed to load collections'))
      .finally(() => setLoading(false));
  }, [slug]);

  if (loading) {
    return <div className="publicCollections__loading">Loading collections...</div>;
  }

  if (error) {
    return <div className="publicCollections__error">{error}</div>;
  }

  if (collections.length === 0) {
    return (
      <div className="publicCollections__empty">
        <p>No public collections available.</p>
      </div>
    );
  }

  return (
    <div className="publicCollections">
      <h1 className="publicCollections__title">Collections</h1>
      <div className="publicCollections__grid">
        {collections.map((collection) => (
          <button
            key={collection.id}
            className="publicCollections__card"
            onClick={() => navigate(`/public/${slug}/collections/${collection.id}`)}
          >
            {collection.heroImageUrl && (
              <div className="publicCollections__imageWrap">
                <img src={collection.heroImageUrl} alt={collection.name} className="publicCollections__image" />
              </div>
            )}
            <div className="publicCollections__content">
              <h2 className="publicCollections__name">{collection.name}</h2>
              {collection.description && (
                <p className="publicCollections__description">{collection.description}</p>
              )}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

export default PublicCollectionsView;
