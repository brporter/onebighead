import { useMemo, useCallback, useEffect, useRef, useState } from 'react';
import type { PropertySuggestionsResponse } from '../../api/suggestions';
import { logError } from '../../utils/errorUtils';
import type { SuggestionGateway } from '../contracts';
import { LruCache } from '../shared/LruCache';

function appendSuggestion(values: string[], value: string): string[] {
  const trimmed = value.trim();
  return !trimmed || values.includes(trimmed) ? values : [...values, trimmed].sort();
}

interface SuggestionRequest {
  synchronize: boolean;
  additions: PropertySuggestionsResponse;
  promise: Promise<void>;
}

export function useSuggestions(gateway: SuggestionGateway) {
  const [suggestions, setSuggestions] = useState<PropertySuggestionsResponse>({ categories: [], names: [] });
  const cache = useRef(new LruCache<number, PropertySuggestionsResponse>(20));
  const activeCollection = useRef<number | null>(null);
  const requests = useRef(new Map<number, SuggestionRequest>());
  const timers = useRef(new Map<number, ReturnType<typeof setTimeout>>());
  const mounted = useRef(true);

  useEffect(() => {
    const pendingTimers = timers.current;
    const pendingRequests = requests.current;
    mounted.current = true;
    return () => {
      mounted.current = false;
      pendingTimers.forEach(clearTimeout);
      pendingTimers.clear();
      pendingRequests.clear();
    };
  }, []);

  const fetchSuggestions = useCallback((id: number, synchronize: boolean): Promise<void> => {
    const pending = requests.current.get(id);
    // A plain read must not supersede a recomputation already in progress.
    if (!synchronize && pending?.synchronize) return pending.promise;
    const request: SuggestionRequest = { synchronize, additions: pending?.additions ?? { categories: [], names: [] }, promise: Promise.resolve() };
    requests.current.set(id, request);
    request.promise = (async () => {
      try {
        const result = await (synchronize ? gateway.sync(id) : gateway.get(id));
        if (requests.current.get(id) !== request) return;
        const sorted = {
          categories: [...new Set([...result.categories, ...request.additions.categories])].sort(),
          names: [...new Set([...result.names, ...request.additions.names])].sort(),
        };
        cache.current.set(id, sorted);
        if (activeCollection.current === id) setSuggestions(sorted);
      } catch (error) {
        if (requests.current.get(id) === request) logError('Failed to load property suggestions', error);
      } finally {
        if (requests.current.get(id) === request) requests.current.delete(id);
      }
    })();
    return request.promise;
  }, [gateway]);

  const loadPropertySuggestions = useCallback(async (id: number) => {
    if (!mounted.current) return;
    activeCollection.current = id;
    const cached = cache.current.get(id);
    setSuggestions(cached ?? requests.current.get(id)?.additions ?? { categories: [], names: [] });
    if (!cached) await fetchSuggestions(id, false);
  }, [fetchSuggestions]);

  const syncPropertySuggestions = useCallback(async (id: number) => {
    if (!mounted.current) return;
    // Debounce independently: editing another collection must not cancel this one.
    clearTimeout(timers.current.get(id));
    timers.current.set(id, setTimeout(() => {
      timers.current.delete(id);
      void fetchSuggestions(id, true);
    }, 2000));
  }, [fetchSuggestions]);

  const addLocalSuggestion = useCallback((field: keyof PropertySuggestionsResponse, value: string) => {
    if (!mounted.current) return;
    const update = (previous: PropertySuggestionsResponse) => ({ ...previous, [field]: appendSuggestion(previous[field], value) });
    const id = activeCollection.current;
    if (id !== null) {
      const cached = cache.current.get(id);
      if (cached) cache.current.set(id, update(cached));
      const pending = requests.current.get(id);
      if (pending) pending.additions = update(pending.additions);
    }
    setSuggestions(update);
  }, []);
  const addLocalCategorySuggestion = useCallback((value: string) => addLocalSuggestion('categories', value), [addLocalSuggestion]);
  const addLocalNameSuggestion = useCallback((value: string) => addLocalSuggestion('names', value), [addLocalSuggestion]);

  return useMemo(() => ({ propertyCategorySuggestions: suggestions.categories, propertyNameSuggestions: suggestions.names,
    loadPropertySuggestions, syncPropertySuggestions, addLocalCategorySuggestion, addLocalNameSuggestion }), [suggestions.categories, suggestions.names, loadPropertySuggestions, syncPropertySuggestions, addLocalCategorySuggestion, addLocalNameSuggestion]);
}
