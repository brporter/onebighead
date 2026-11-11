import { useCallback, useEffect, useState } from 'react';
import { getErrorMessage } from './errorUtils';

interface AsyncDataResult<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

type Fetcher<T> = (signal: AbortSignal) => Promise<T>;

/**
 * Hook for fetching async data with loading/error state management.
 *
 * @param fetcher - A stable (useCallback-wrapped) async function that returns
 *   data. When its identity changes, a new fetch is triggered automatically.
 *   Pass `null` to skip fetching (e.g. when required params aren't ready).
 *   Forward the supplied signal to the API adapter to cancel network work on
 *   navigation. Results are ignored after cleanup even if the adapter cannot abort.
 * @returns `{ data, loading, error, retry }`; retry cancels the previous request.
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
  fetcher: Fetcher<T> | null,
): AsyncDataResult<T> & { retry: () => void } {
  const [revision, setRevision] = useState(0);
  const retry = useCallback(() => setRevision(previous => previous + 1), []);
  const pending: AsyncDataResult<T> = { data: null, loading: fetcher !== null, error: null };
  const [state, setState] = useState({ fetcher, revision, result: pending });

  // Reset before committing a new route, including returning to the same fetcher
  // after an idle state. An effect-only reset can expose the previous entity.
  if (state.fetcher !== fetcher || state.revision !== revision) setState({ fetcher, revision, result: pending });

  useEffect(() => {
    if (fetcher === null) return;
    const controller = new AbortController();

    const load = async () => {
      try {
        const data = await fetcher(controller.signal);
        if (!controller.signal.aborted) {
          setState({ fetcher, revision, result: { data, loading: false, error: null } });
        }
      } catch (cause) {
        if (!controller.signal.aborted) {
          setState({ fetcher, revision, result: { data: null, loading: false, error: getErrorMessage(cause, 'An error occurred') } });
        }
      }
    };
    void load();

    return () => controller.abort();
  }, [fetcher, revision]);

  return { ...state.result, retry };
}
