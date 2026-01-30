import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useData } from '../contexts/DataContext';
import CollectionList from '../components/collection/CollectionList';

function CollectionView() {
  const navigate = useNavigate();
  const {
    collections,
    collectionsLoading,
    loadCollections,
  } = useData();

  useEffect(() => {
    loadCollections();
  }, [loadCollections]);

  useEffect(() => {
    // Redirect to setup if user has no collections
    if (!collectionsLoading && collections.length === 0) {
      navigate('/setup', { replace: true });
      return;
    }
    
    // Auto-navigate to single collection
    if (!collectionsLoading && collections.length === 1) {
      navigate(`/collections/${collections[0].collectionId}`, { replace: true });
    }
  }, [collections, collectionsLoading, navigate]);

  if (collectionsLoading) {
    return <div className="app__loading">Loading collections...</div>;
  }

  if (collections.length === 0) {
    return <div className="app__loading">Redirecting to setup...</div>;
  }

  return (
    <CollectionList
      collections={collections}
      onSelect={(collection) => navigate(`/collections/${collection.collectionId}`)}
    />
  );
}

export default CollectionView;
