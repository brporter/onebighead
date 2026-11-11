import { useMemo, useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import type { Item } from '../../utils/types';
import { ApiError, type RequestOptions } from '../../api/transport';
import type { ItemGateway } from '../contracts';
import type { ResourceLoadOptions } from '../shared/useAsyncResource';
import { ItemRecords, resolveItemRecords } from './ItemRecords';
import { useCategoryItems } from './useCategoryItems';

export function useItems(gateway: ItemGateway, syncSuggestions: (collectionId: number) => Promise<void>) {
  const [records] = useState(() => new ItemRecords());
  const itemDetails = useSyncExternalStore(records.subscribe, records.getSnapshot);
  const { items: categoryItems, itemsLoading, itemsError, loadCategory, invalidate, clearCache } = useCategoryItems(gateway, records);
  const items = useMemo(() => resolveItemRecords(categoryItems, itemDetails), [categoryItems, itemDetails]);
  const lifetime = useRef({ mounted: true });
  const activeSource = useRef<{ type: 'category' | 'item'; id: number } | null>(null);

  useEffect(() => {
    const current = lifetime.current;
    current.mounted = true;
    return () => {
      current.mounted = false;
      records.invalidate();
    };
  }, [records]);

  const invalidateItemCache = useCallback(() => {
    if (!lifetime.current.mounted) return;
    records.invalidate();
    invalidate(activeSource.current?.type === 'category');
  }, [records, invalidate]);

  const loadItemsForCategory = useCallback(async (categoryId: number, options?: ResourceLoadOptions) => {
    activeSource.current = { type: 'category', id: categoryId };
    await loadCategory(categoryId, options);
  }, [loadCategory]);

  const loadItemById = useCallback(async (id: number, options?: RequestOptions): Promise<Item | null> => {
    if (!lifetime.current.mounted) throw new DOMException('This item session has ended.', 'AbortError');
    activeSource.current = { type: 'item', id };
    const revision = records.beginRead(id);
    const accept = (item: Item | null) => {
      if (options?.signal?.aborted || !records.accept([[id, item]], revision)) return;
      clearCache();
    };
    try {
      options?.signal?.throwIfAborted();
      const item = await gateway.getById(id, options);
      const result = item.id === id ? item : null;
      accept(result);
      return result;
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        accept(null);
        return null;
      }
      throw error;
    }
  }, [gateway, records, clearCache]);

  const refreshLoadedItems = useCallback(async (options: ResourceLoadOptions) => {
    const source = activeSource.current;
    records.invalidate();
    invalidate(false);
    if (source?.type === 'category') await loadItemsForCategory(source.id, options);
    else if (source?.type === 'item') {
      const item = await loadItemById(source.id, options);
      if (item === null) throw new Error('The selected item is no longer available. Return to the collection to continue.');
    }
  }, [records, invalidate, loadItemsForCategory, loadItemById]);

  const invalidateAndSync = useCallback((collectionId: number) => {
    invalidateItemCache();
    void syncSuggestions(collectionId);
  }, [invalidateItemCache, syncSuggestions]);

  const addItem = useCallback(async (item: Item): Promise<number> => {
    const created = await gateway.create(item);
    if (!lifetime.current.mounted) return created.id!;
    records.write(created.id!, created);
    invalidateAndSync(created.collectionId);
    return created.id!;
  }, [gateway, invalidateAndSync, records]);

  const updateItem = useCallback(async (id: number, updates: Partial<Item>) => {
    const current = records.getSnapshot().get(id) ?? await gateway.getById(id);
    if (!lifetime.current.mounted) throw new DOMException('This item session has ended.', 'AbortError');
    const updated = await gateway.update(id, { ...current, ...updates });
    if (!lifetime.current.mounted) return updated;
    records.write(id, updated);
    invalidateAndSync(updated.collectionId);
    return updated;
  }, [gateway, invalidateAndSync, records]);

  const deleteItem = useCallback(async (id: number) => {
    const current = records.getSnapshot().get(id);
    await gateway.delete(id);
    if (!lifetime.current.mounted) return;
    records.write(id, null);
    invalidateItemCache();
    if (current) void syncSuggestions(current.collectionId);
  }, [gateway, invalidateItemCache, syncSuggestions, records]);

  return useMemo(() => ({ items, itemDetails, itemsLoading, itemsError, loadItemsForCategory, loadItemById, addItem, updateItem, deleteItem, invalidateItemCache, refreshLoadedItems }), [items, itemDetails, itemsLoading, itemsError, loadItemsForCategory, loadItemById, addItem, updateItem, deleteItem, invalidateItemCache, refreshLoadedItems]);
}
