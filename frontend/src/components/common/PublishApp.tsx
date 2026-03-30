import { useCallback } from 'react';
import { useData } from '../../contexts/useData';
import { usePublish } from '../../contexts/usePublish';
import { PublishResolver } from './PublishResolver';

export function PublishApp() {
  const { loadCollections, loadCategoriesForCollection, currentCollection } = useData();
  const { pendingIntent, clearIntent } = usePublish();

  const handlePublishComplete = useCallback(() => {
    loadCollections();
    if (currentCollection) {
      loadCategoriesForCollection(currentCollection.collectionId);
    }
  }, [loadCollections, loadCategoriesForCollection, currentCollection]);

  return (
    <PublishResolver
      intent={pendingIntent}
      onClearIntent={clearIntent}
      onComplete={handlePublishComplete}
    />
  );
}
