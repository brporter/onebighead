import { useState } from 'react';
import type { Collection } from '../../utils/types';
import type { UnpublishPreviewResponse } from '../../utils/types';
import { useData } from '../../contexts/useData';
import { PublishButton, PublicBadge, PublishConfirmModal, UnpublishConfirmModal, SlugSetupModal } from '../common';
import '../../styles/components/CollectionList.css';

interface CollectionListProps {
  collections: Collection[];
  onSelect: (collection: Collection) => void;
}

function CollectionList({ collections, onSelect }: CollectionListProps) {
  const {
    publishCollection,
    unpublishCollection,
    getUnpublishCollectionPreview,
    loadCollections,
  } = useData();

  const [publishTarget, setPublishTarget] = useState<Collection | null>(null);
  const [unpublishTarget, setUnpublishTarget] = useState<Collection | null>(null);
  const [unpublishPreview, setUnpublishPreview] = useState<UnpublishPreviewResponse | null>(null);
  const [showSlugSetup, setShowSlugSetup] = useState(false);

  function handlePublishClick(collection: Collection) {
    setPublishTarget(collection);
  }

  async function handlePublishConfirm(includeChildren: boolean) {
    if (!publishTarget) return;
    const result = await publishCollection(publishTarget.collectionId, includeChildren);
    setPublishTarget(null);
    if (result.requiresSlugSetup) {
      setShowSlugSetup(true);
      return;
    }
    await loadCollections();
  }

  function handlePublishCancel() {
    setPublishTarget(null);
  }

  async function handleUnpublishClick(collection: Collection) {
    const preview = await getUnpublishCollectionPreview(collection.collectionId);
    setUnpublishPreview(preview);
    setUnpublishTarget(collection);
  }

  async function handleUnpublishConfirm() {
    if (!unpublishTarget) return;
    await unpublishCollection(unpublishTarget.collectionId);
    setUnpublishTarget(null);
    setUnpublishPreview(null);
    await loadCollections();
  }

  function handleUnpublishCancel() {
    setUnpublishTarget(null);
    setUnpublishPreview(null);
  }

  async function handleSlugConfirm(_slug: string) {
    setShowSlugSetup(false);
    await loadCollections();
  }

  return (
    <div className="collectionList">
      <h2 className="collectionList__title">Your Collections</h2>
      <p className="collectionList__subtitle">Select a collection to view its items</p>
      <div className="collectionList__grid">
        {collections.map((collection) => (
          <button
            key={collection.collectionId}
            className="collectionList__card"
            onClick={() => onSelect(collection)}
          >
            {collection.effectiveIsPublic ? (
              <PublicBadge
                effectiveIsPublic={collection.effectiveIsPublic}
                onUnpublish={() => handleUnpublishClick(collection)}
                className="collectionList__badge"
              />
            ) : (
              <PublishButton
                onPublish={() => handlePublishClick(collection)}
                className="collectionList__publish-btn"
              />
            )}

            {collection.heroImageUrl && (
              <div className="collectionList__imageWrap">
                <img
                  src={collection.heroImageUrl}
                  alt={collection.name}
                  className="collectionList__image"
                />
              </div>
            )}
            <div className="collectionList__content">
              <h3 className="collectionList__name">{collection.name}</h3>
              {collection.description && (
                <p className="collectionList__description">{collection.description}</p>
              )}
            </div>
          </button>
        ))}
      </div>

      {publishTarget && (
        <PublishConfirmModal
          entityType="collection"
          entityName={publishTarget.name}
          itemCount={0}
          categoryCount={0}
          onConfirm={handlePublishConfirm}
          onCancel={handlePublishCancel}
        />
      )}

      {unpublishTarget && unpublishPreview && (
        <UnpublishConfirmModal
          entityType="collection"
          entityName={unpublishTarget.name}
          affectedPublicItems={unpublishPreview.affectedPublicItems}
          affectedPublicCategories={unpublishPreview.affectedPublicCategories}
          onConfirm={handleUnpublishConfirm}
          onCancel={handleUnpublishCancel}
        />
      )}

      {showSlugSetup && (
        <SlugSetupModal
          onConfirm={handleSlugConfirm}
          onCancel={() => setShowSlugSetup(false)}
        />
      )}
    </div>
  );
}

export default CollectionList;
