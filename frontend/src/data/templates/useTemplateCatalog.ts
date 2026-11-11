import { useCallback } from 'react';
import type { ItemTemplate } from '../../utils/types';
import type { RequestOptions } from '../../api/transport';
import { useAsyncData } from '../../utils/useAsyncData';

export interface TemplateCatalogPort {
  fetchItemTemplates: (options?: RequestOptions) => Promise<ItemTemplate[]>;
  loadCollectionTemplates: (id: number, options?: RequestOptions) => Promise<ItemTemplate[]>;
}

/** Collection entries take precedence when the same template occurs in both sources. */
export function mergeTemplates(collection: ItemTemplate[], library: ItemTemplate[]) {
  return [...new Map([...library, ...collection].map(template => [template.itemTemplateId, template])).values()]
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function useTemplateCatalog(collectionId: number, port: TemplateCatalogPort) {
  const { fetchItemTemplates, loadCollectionTemplates } = port;
  const fetchCatalog = useCallback(async (signal: AbortSignal) => {
    const [collection, library] = await Promise.all([
      loadCollectionTemplates(collectionId, { signal }), fetchItemTemplates({ signal }),
    ]);
    return { collection, library, available: mergeTemplates(collection, library) };
  }, [collectionId, fetchItemTemplates, loadCollectionTemplates]);
  return useAsyncData(fetchCatalog);
}
