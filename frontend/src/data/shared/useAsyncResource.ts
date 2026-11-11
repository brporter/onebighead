import { useCallback, useLayoutEffect, useRef, useState } from 'react';
import { getErrorMessage } from '../../utils/errorUtils';

export interface ResourceLoadOptions { signal?: AbortSignal; throwOnError?: boolean }

/** Owns request state; only the latest request may publish a result. */
export function useAsyncResource<T>(initialData: T, fallbackError: string, initiallyLoading = false) {
  const [data, setData] = useState(initialData);
  const [loading, setLoading] = useState(initiallyLoading);
  const [error, setError] = useState<string | null>(null);
  const lifecycle = useRef({ mounted: true, request: 0, changes: null as Array<(value: T) => T> | null });

  // Activate before descendant passive effects start reads, including StrictMode replay.
  useLayoutEffect(() => {
    const current = lifecycle.current;
    current.mounted = true;
    return () => {
      current.mounted = false;
      current.request++;
      current.changes = null;
    };
  }, []);

  // Confirmed changes are applied immediately, then replayed over an older read.
  // Callers supply pure, idempotent updates (upsert/remove), never append blindly.
  const mutate = useCallback((update: (value: T) => T) => {
    const current = lifecycle.current;
    if (!current.mounted) return false;
    current.changes?.push(update);
    setData(update);
    return true;
  }, []);

  const load = useCallback(async (fetcher: () => Promise<T>, options: ResourceLoadOptions = {}, accepted?: (result: T) => void) => {
    const current = lifecycle.current;
    if (!current.mounted) return;
    const version = ++current.request;
    const changes: Array<(value: T) => T> = [];
    current.changes = changes;
    setLoading(true);
    setError(null);
    try {
      options.signal?.throwIfAborted();
      const result = await fetcher();
      options.signal?.throwIfAborted();
      if (version === current.request) {
        const next = changes.reduce<T>((value, update) => update(value), result);
        setData(next);
        accepted?.(next);
      }
    } catch (cause) {
      if (version === current.request && !options.signal?.aborted) setError(getErrorMessage(cause, fallbackError));
      if (options.throwOnError) throw cause;
    } finally {
      if (version === current.request) {
        current.changes = null;
        setLoading(false);
      }
    }
  }, [fallbackError]);

  return { data, setData, mutate, loading, error, load };
}
