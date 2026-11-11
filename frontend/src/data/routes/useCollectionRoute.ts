import { useEffect, useRef } from 'react';
import type { Category, Collection } from '../../utils/types';

export interface CollectionRoutePort {
  collections: Collection[];
  collectionsLoading: boolean;
  collectionsError: string | null;
  loadCollections: () => Promise<void>;
  currentCollection: Collection | null;
  setCurrentCollection: (collection: Collection) => void;
  categories: Category[];
  categoriesLoading: boolean;
  loadCategoriesForCollection: (id: number) => Promise<void>;
  loadPropertySuggestions: (id: number) => Promise<void>;
}

/** Coordinates route selection without owning rendering or navigation. */
export function useCollectionRoute(collectionId: number, data: CollectionRoutePort) {
  const { collections, collectionsLoading, collectionsError, loadCollections,
    currentCollection, setCurrentCollection, categories, categoriesLoading,
    loadCategoriesForCollection, loadPropertySuggestions } = data;
  const requested = useRef(false);
  const collection = collections.find(value => value.collectionId === collectionId);

  useEffect(() => {
    if (!collectionsLoading && !collectionsError && collections.length === 0 && !requested.current) {
      requested.current = true;
      void loadCollections();
    }
  }, [collectionsLoading, collectionsError, collections.length, loadCollections]);

  useEffect(() => {
    if (collection && currentCollection?.collectionId !== collectionId) {
      setCurrentCollection(collection);
      void loadCategoriesForCollection(collectionId);
      void loadPropertySuggestions(collectionId);
    }
  }, [collection, currentCollection, collectionId, setCurrentCollection, loadCategoriesForCollection, loadPropertySuggestions]);

  return {
    collection,
    categories: categories.filter(category => category.collectionId === collectionId),
    categoriesPending: categoriesLoading || currentCollection?.collectionId !== collectionId,
  };
}
