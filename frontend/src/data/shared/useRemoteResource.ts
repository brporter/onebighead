import { useCallback, useEffect, useRef } from 'react';
import { useAsyncResource } from './useAsyncResource';

/** Reads a mounted resource and cancels obsolete refreshes or a retired workspace. */
export function useRemoteResource<T>(read: (options: { signal: AbortSignal }) => Promise<T>, fallbackError: string) {
  const resource = useAsyncResource<T | null>(null, fallbackError, true);
  const { load } = resource;
  const active = useRef<AbortController | null>(null);
  const reload = useCallback(() => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    return load(() => read({ signal: controller.signal }), { signal: controller.signal });
  }, [load, read]);
  useEffect(() => { void reload(); return () => active.current?.abort(); }, [reload]);
  return { ...resource, reload };
}
