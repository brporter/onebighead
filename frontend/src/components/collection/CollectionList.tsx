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
          <div
            key={collection.collectionId}
            className="collectionList__card"
            role="button"
            tabIndex={0}
            onClick={() => onSelect(collection)}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(collection); } }}
          >
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
          </div>
        ))}
      </div>
    </div>
  );
}

export default CollectionList;
