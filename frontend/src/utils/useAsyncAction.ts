import { useEffect, useRef, useState } from 'react';
import { getErrorMessage } from './errorUtils';

/** Keeps a form open on failure and allows only one action at a time. */
export function useAsyncAction() {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const busy = useRef(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  async function run<T>(action: () => T | Promise<T>, fallbackError: string, onSuccess?: (result: T) => void | Promise<void>) {
    if (busy.current) return;
    busy.current = true;
    setPending(true);
    setError(null);
    try {
      const result = await action();
      if (mounted.current) await onSuccess?.(result);
    } catch (cause) {
      if (mounted.current) setError(getErrorMessage(cause, fallbackError));
    } finally {
      busy.current = false;
      if (mounted.current) setPending(false);
    }
  }

  return { pending, error, run };
}
