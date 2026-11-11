import { useMemo, useCallback, useEffect, useRef, useState } from 'react';
import type { Collection, SetupCollectionRequest } from '../../utils/types';
import type { UpdateCollectionRequest } from '../../api/collections';
import type { CollectionGateway } from '../contracts';
import { useAsyncResource, type ResourceLoadOptions } from '../shared/useAsyncResource';
import { upsertBy } from '../shared/upsertBy';

export function useCollections(gateway: CollectionGateway) {
  const [currentCollection, setCurrentCollection] = useState<Collection | null>(null);
  const { data: collections, mutate, loading: collectionsLoading, error: collectionsError, load } =
    useAsyncResource<Collection[]>([], 'Failed to fetch collections', true);
  const pending = useRef<Promise<void> | null>(null);
  // StrictMode retires the resource request during effect cleanup. A replayed
  // reader must start a fresh request instead of joining that retired promise.
  useEffect(() => () => { pending.current = null; }, []);

  const loadCollections = useCallback((options?: ResourceLoadOptions) => {
    const refresh = () => load(() => gateway.getAll(options), options, next => {
      setCurrentCollection(previous => previous === null ? null : next.find(collection => collection.collectionId === previous.collectionId) ?? null);
    });
    // A required post-write refresh must not reuse a read started before the write.
    if (options || !pending.current) {
      const request = refresh().finally(() => { if (pending.current === request) pending.current = null; });
      pending.current = request;
    }
    return pending.current;
  }, [gateway, load]);

  const addCollection = useCallback(async (name: string, description?: string, heroImageUrl?: string) => {
    const created = await gateway.create({ name, description, heroImageUrl });
    mutate(previous => upsertBy(previous, created, 'collectionId'));
    return created;
  }, [gateway, mutate]);

  const setupCollection = useCallback(async (request: SetupCollectionRequest) => {
    const created = await gateway.setup(request);
    mutate(previous => upsertBy(previous, created, 'collectionId'));
    return created;
  }, [gateway, mutate]);

  const updateCollection = useCallback(async (id: number, request: UpdateCollectionRequest) => {
    const updated = await gateway.update(id, request);
    if (mutate(previous => upsertBy(previous, updated, 'collectionId')))
      setCurrentCollection(previous => previous?.collectionId === id ? updated : previous);
  }, [gateway, mutate]);

  const deleteCollection = useCallback(async (id: number) => {
    await gateway.delete(id);
    if (mutate(previous => previous.filter(collection => collection.collectionId !== id)))
      setCurrentCollection(previous => previous?.collectionId === id ? null : previous);
  }, [gateway, mutate]);

  return useMemo(() => ({ currentCollection, setCurrentCollection, collections, collectionsLoading, collectionsError,
    loadCollections, addCollection, setupCollection, updateCollection, deleteCollection }), [currentCollection, setCurrentCollection, collections, collectionsLoading, collectionsError, loadCollections, addCollection, setupCollection, updateCollection, deleteCollection]);
}
