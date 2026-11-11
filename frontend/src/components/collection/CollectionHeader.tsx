import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import type { Collection } from '../../utils/types';
import '../../styles/components/CollectionHeader.css';

interface CollectionHeaderProps {
  collection: Pick<Collection, 'name' | 'description'>;
  homeHref?: string;
  showAllCollections: boolean;
  actions?: ReactNode;
}

export function CollectionHeader({ collection, homeHref, showAllCollections, actions }: CollectionHeaderProps) {
  return <header className="collection-header">
    {showAllCollections && <Link to="/collections" className="collection-header__back">← All Collections</Link>}
    <div className="collection-header__heading">
      <h1 className="collection-header__title">
        {homeHref ? <Link to={homeHref}>{collection.name}</Link> : collection.name}
      </h1>
      {actions && <div className="collection-header__actions">{actions}</div>}
    </div>
    {collection.description && <p className="collection-header__description">{collection.description}</p>}
  </header>;
}
