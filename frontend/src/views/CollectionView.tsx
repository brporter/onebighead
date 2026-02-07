import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useData } from '../contexts/DataContext';
import CollectionList from '../components/collection/CollectionList';
import { Loading } from '../components/common';

function CollectionView() {
  const navigate = useNavigate();
  const {
    collections,
    collectionsLoading,
    collectionsError,
    loadCollections,
  } = useData();

  useEffect(() => {
    loadCollections();
  }, [loadCollections]);

  useEffect(() => {
    // Don't redirect if there was an error loading collections - show error instead
    if (collectionsError) {
      return;
    }

    // Redirect to setup if user has no collections
    if (!collectionsLoading && collections.length === 0) {
      navigate('/setup', { replace: true });
      return;
    }

    // Auto-navigate to single collection
    if (!collectionsLoading && collections.length === 1) {
      navigate(`/collections/${collections[0].collectionId}`, { replace: true });
    }
  }, [collections, collectionsLoading, collectionsError, navigate]);

  if (collectionsLoading) {
    return <Loading message="Loading collections..." />;
  }

  if (collectionsError) {
    return (
      <div className="app__error">
        <p>Error loading collections: {collectionsError}</p>
        <button onClick={() => loadCollections()}>Retry</button>
      </div>
    );
  }

  if (collections.length === 0) {
    return <Loading message="Redirecting to setup..." />;
  }

  return (
    <CollectionList
      collections={collections}
      onSelect={(collection) => navigate(`/collections/${collection.collectionId}`)}
    />
  );
}

export default CollectionView;
