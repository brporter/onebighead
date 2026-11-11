import { useCallback, useEffect, useRef } from 'react';
import type { Item } from '../../utils/types';
import type { ItemGateway } from '../contracts';
import { LruCache } from '../shared/LruCache';
import { useAsyncResource, type ResourceLoadOptions } from '../shared/useAsyncResource';
import type { ItemRecords } from './ItemRecords';

interface CachedItems { items: Item[]; etag: string | null }

/** Category membership comes from list reads; individual records never add list members. */
export function useCategoryItems(gateway: Pick<ItemGateway, 'getAll'>, records: ItemRecords) {
  const resource = useAsyncResource<Item[]>([], 'Failed to fetch items');
  const { setData, load } = resource;
  const cache = useRef(new LruCache<number, CachedItems>(20));
  const lifetime = useRef({ mounted: true, request: 0, generation: 0, pending: false,
    active: null as { id: number; options?: ResourceLoadOptions } | null });

  useEffect(() => {
    const current = lifetime.current;
    current.mounted = true;
    return () => { current.mounted = false; current.request++; };
  }, []);

  const clearCache = useCallback(() => { cache.current.clear(); }, []);

  const loadCategory = useCallback(async (id: number, options?: ResourceLoadOptions) => {
    const current = lifetime.current;
    if (!current.mounted) return;
    const cached = cache.current.get(id);
    if (cached || current.active?.id !== id) setData(cached?.items ?? []);
    current.active = { id, options };
    current.pending = true;
    const request = ++current.request;
    try {
      await load(async () => {
        // A confirmed write invalidates list membership. Retry the read, never the write.
        for (;;) {
          const generation = current.generation;
          const revision = records.beginRead();
          const existing = cache.current.get(id);
          try {
            const result = await gateway.getAll({ categoryId: id, includeDescendants: true, etag: existing?.etag ?? undefined }, options);
            options?.signal?.throwIfAborted();
            if (!current.mounted || request !== current.request) return [];
            if (generation !== current.generation) continue;
            if (result.notModified && !existing) throw new Error('Received unchanged items without a cached response');
            const next = result.notModified ? existing! : result;
            cache.current.set(id, next);
            if (!result.notModified) records.accept(next.items.map(item => [item.id!, item]), revision);
            return next.items;
          } catch (error) {
            if (current.mounted && request === current.request && !options?.signal?.aborted && generation !== current.generation) continue;
            throw error;
          }
        }
      }, options);
    } finally {
      if (request === current.request) current.pending = false;
    }
  }, [gateway, records, load, setData]);

  const invalidate = useCallback((revalidate: boolean) => {
    const current = lifetime.current;
    if (!current.mounted) return;
    clearCache();
    current.generation++;
    const active = current.active;
    if (revalidate && active && !current.pending && !active.options?.signal?.aborted) {
      void loadCategory(active.id, { signal: active.options?.signal });
    }
  }, [clearCache, loadCategory]);

  return { items: resource.data, itemsLoading: resource.loading, itemsError: resource.error,
    loadCategory, invalidate, clearCache };
}
