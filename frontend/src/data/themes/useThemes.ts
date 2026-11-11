import { useMemo, useCallback } from 'react';
import type { CollectionTheme } from '../../utils/types';
import type { ThemeGateway } from '../contracts';
import { useAsyncResource } from '../shared/useAsyncResource';

export function useThemes(gateway: ThemeGateway) {
  const { data: themes, loading: themesLoading, error: themesError, load } =
    useAsyncResource<CollectionTheme[]>([], 'Failed to fetch themes');
  const loadThemes = useCallback(() => load(() => gateway.getAll()), [gateway, load]);
  return useMemo(() => ({ themes, themesLoading, themesError, loadThemes }), [themes, themesLoading, themesError, loadThemes]);
}
