import type { Collection } from '../../utils/types';
import { PublishButton, PublicBadge } from '../common';
import { usePublish } from '../../contexts/usePublish';
import '../../styles/components/CollectionList.css';

interface CollectionListProps {
  collections: Collection[];
  onSelect: (collection: Collection) => void;
}

function CollectionList({ collections, onSelect }: CollectionListProps) {
  const { requestPublish, requestUnpublish } = usePublish();

  function handlePublishClick(collection: Collection) {
    requestPublish([{ type: 'collection', id: collection.collectionId }]);
  }

  function handleUnpublishClick(collection: Collection) {
    requestUnpublish([{ type: 'collection', id: collection.collectionId }]);
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
    </div>
  );
}

export default CollectionList;
