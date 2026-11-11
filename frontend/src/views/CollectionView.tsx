import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useCollectionsData } from '../contexts/useData';
import CollectionList from '../components/collection/CollectionList';
import { ContentState } from '../components/common';

function CollectionView() {
  const navigate = useNavigate();
  const {
    collections,
    collectionsLoading,
    collectionsError,
    loadCollections,
  } = useCollectionsData();

  useEffect(() => {
    void loadCollections();
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
    return <ContentState kind="loading" title="Loading collections..." />;
  }

  if (collectionsError) {
    return <ContentState kind="error" title="Unable to load collections"
      action={<button type="button" onClick={() => void loadCollections()}>Try again</button>}>{collectionsError}</ContentState>;
  }

  if (collections.length === 0) {
    return <ContentState kind="loading" title="Redirecting to setup..." />;
  }

  return (
    <CollectionList
      collections={collections}
      onSelect={(collection) => navigate(`/collections/${collection.collectionId}`)}
    />
  );
}

export default CollectionView;
