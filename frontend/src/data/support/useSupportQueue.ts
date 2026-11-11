import { useCallback, useEffect } from 'react';
import { useAsyncData } from '../../utils/useAsyncData';
import { useAsyncAction } from '../../utils/useAsyncAction';
import type { SupportQueuePort, SupportQueueQuery } from './ports';

export const SUPPORT_PAGE_SIZE = 20;

export function useSupportQueue(query: SupportQueueQuery, gateway: SupportQueuePort, onPageChange: (page: number) => void) {
  const fetch = useCallback((signal: AbortSignal) => gateway.list({
    status: query.status || undefined, includeDeleted: query.includeDeleted, limit: SUPPORT_PAGE_SIZE, offset: query.page * SUPPORT_PAGE_SIZE,
  }, { signal }), [gateway, query]);
  const resource = useAsyncData(fetch);
  const action = useAsyncAction();
  const totalPages = Math.max(1, Math.ceil((resource.data?.total ?? 0) / SUPPORT_PAGE_SIZE));
  useEffect(() => {
    if (resource.data && query.page >= totalPages) onPageChange(totalPages - 1);
  }, [resource.data, query.page, totalPages, onPageChange]);
  return {
    ...resource, totalPages, pending: action.pending, actionError: action.error,
    remove: (id: number) => action.run(() => gateway.remove(id), 'Failed to delete request', resource.retry),
  };
}
