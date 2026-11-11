import { useCallback } from 'react';
import type { RequestOptions } from '../../api/transport';
import { useAsyncData } from '../../utils/useAsyncData';

export interface TemplateRecommendationsPort {
  getCategoryTemplates: (id: number, options?: RequestOptions) => Promise<number[]>;
}

export function useTemplateRecommendations(categoryId: number | null, port: TemplateRecommendationsPort) {
  const { getCategoryTemplates } = port;
  const fetchIds = useCallback((signal: AbortSignal) => getCategoryTemplates(categoryId!, { signal }),
    [categoryId, getCategoryTemplates]);
  return useAsyncData(categoryId === null ? null : fetchIds);
}
