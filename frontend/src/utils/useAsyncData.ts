import { useEffect, useState } from 'react';

interface AsyncDataResult<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

type FetchState<T> =
  | { status: 'loading' }
  | { status: 'success'; data: T }
  | { status: 'error'; error: string }
  | { status: 'idle' };

/**
 * Hook for fetching async data with loading/error state management.
 *
 * @param fetcher - A stable (useCallback-wrapped) async function that returns
 *   data. When its identity changes, a new fetch is triggered automatically.
 *   Pass `null` to skip fetching (e.g. when required params aren't ready).
 * @returns `{ data, loading, error }`
 *
 * @example
 * ```ts
 * const fetchStats = useCallback(
 *   () => collectionsApi.getStatistics(collectionId),
 *   [collectionId],
 * );
 * const { data: stats, loading, error } = useAsyncData(fetchStats);
 * ```
 */
export function useAsyncData<T>(
  fetcher: (() => Promise<T>) | null,
): AsyncDataResult<T> {
  const [state, setState] = useState<FetchState<T>>(
    fetcher === null ? { status: 'idle' } : { status: 'loading' },
  );

  useEffect(() => {
    if (fetcher === null) {
      // Schedule state reset as a microtask to avoid synchronous setState in effect
      void Promise.resolve().then(() => setState({ status: 'idle' }));
      return;
    }

    let cancelled = false;

    // Signal loading via microtask
    void Promise.resolve().then(() => {
      if (!cancelled) setState({ status: 'loading' });
    });

    fetcher()
      .then((data) => {
        if (!cancelled) setState({ status: 'success', data });
      })
      .catch((err) => {
        if (!cancelled) {
          setState({
            status: 'error',
            error: err instanceof Error ? err.message : 'An error occurred',
          });
        }
      });

    return () => { cancelled = true; };
  }, [fetcher]);

  return {
    data: state.status === 'success' ? state.data : null,
    loading: state.status === 'loading',
    error: state.status === 'error' ? state.error : null,
  };
}
