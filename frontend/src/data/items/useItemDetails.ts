import { useCallback, useEffect, useRef } from 'react';
import type { Item } from '../../utils/types';
import type { RequestOptions } from '../../api/transport';
import { useAsyncData } from '../../utils/useAsyncData';

interface ItemDetailsPort {
  itemDetails: ReadonlyMap<number, Item | null>;
  loadItemById: (id: number, options?: RequestOptions) => Promise<Item | null>;
}

export function useItemDetails(collectionId: number, itemId: number, data: ItemDetailsPort, recordView: (id: number) => Promise<void>) {
  const { itemDetails, loadItemById } = data;
  const fetchItem = useCallback(async (signal: AbortSignal) => {
    await loadItemById(itemId, { signal });
  }, [itemId, loadItemById]);
  // Revalidate on entry even when cached, and register this detail as the active item source.
  const resource = useAsyncData(fetchItem);
  const result = itemDetails.get(itemId);
  const item = result?.collectionId === collectionId && result.id === itemId ? result : null;
  const viewedId = item?.id ?? null;
  const lastViewedId = useRef<number | null>(null);

  useEffect(() => {
    if (viewedId !== null && viewedId !== lastViewedId.current) {
      lastViewedId.current = viewedId;
      void recordView(viewedId).catch(() => {});
    }
  }, [viewedId, recordView]);

  return { item, loading: resource.loading && item === null, error: resource.error, retry: resource.retry };
}
