import { useCallback } from 'react';
import type { ItemTemplate } from '../../utils/types';
import type { RequestOptions } from '../../api/transport';
import { useAsyncData } from '../../utils/useAsyncData';
import { useAsyncAction } from '../../utils/useAsyncAction';

export interface TemplateLibraryPort {
  fetchItemTemplates: (options?: RequestOptions) => Promise<ItemTemplate[]>;
  deleteItemTemplate: (id: number) => Promise<void>;
}

export function useTemplateLibrary({ fetchItemTemplates, deleteItemTemplate }: TemplateLibraryPort) {
  const fetcher = useCallback((signal: AbortSignal) => fetchItemTemplates({ signal }), [fetchItemTemplates]);
  const resource = useAsyncData(fetcher);
  const action = useAsyncAction();
  const remove = (id: number) => action.run(() => deleteItemTemplate(id), 'Unable to delete template', resource.retry);
  return { ...resource, refresh: resource.retry, remove, deleting: action.pending, deleteError: action.error };
}
