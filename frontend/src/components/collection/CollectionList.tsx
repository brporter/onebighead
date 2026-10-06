import type { Collection } from '../../utils/types';
import '../../styles/components/CollectionList.css';

interface CollectionListProps {
  collections: Collection[];
  onSelect: (collection: Collection) => void;
}

function CollectionList({ collections, onSelect }: CollectionListProps) {
  return (
    <div className="collectionList">
      <h2 className="collectionList__title">Your Collections</h2>
      <p className="collectionList__subtitle">Select a collection to view its items</p>
      <div className="collectionList__grid">
        {collections.map((collection) => (
          <button
            type="button"
            key={collection.collectionId}
            className="collectionList__card"
            onClick={() => onSelect(collection)}
          >
            {collection.heroImageUrl && (
              <span className="collectionList__imageWrap">
                <img
                  src={collection.heroImageUrl}
                  alt={collection.name}
                  className="collectionList__image"
                />
              </span>
            )}
            <span className="collectionList__content">
              <span className="collectionList__name">{collection.name}</span>
              {collection.description && (
                <span className="collectionList__description">{collection.description}</span>
              )}
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

export default CollectionList;
