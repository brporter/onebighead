import { useCallback, useEffect, useRef, useState } from 'react';
import type { authApi } from '../../api/auth';
import type { CurrentUser } from '../../utils/types';
import { getErrorMessage } from '../../utils/errorUtils';

export type UserSessionPort = Pick<typeof authApi, 'getCurrentUser' | 'logout'>;
export interface SessionRefreshOptions {
  throwOnError?: boolean;
  /** An account-ending action may have committed despite a missing response. */
  endSessionIfAnonymous?: boolean;
}

interface SessionState {
  user: CurrentUser | null;
  loading: boolean;
  error: string | null;
  signedOut: boolean;
}

/** Owns session reads and logout; stale reads cannot restore a signed-out session. */
export function useUserSession({ getCurrentUser, logout: endSession }: UserSessionPort) {
  const [state, setState] = useState<SessionState>({ user: null, loading: true, error: null, signedOut: false });
  const mounted = useRef(false);
  const request = useRef<AbortController | null>(null);
  const logoutRequest = useRef<Promise<void> | null>(null);
  const signedOut = useRef(false);

  const refetch = useCallback(async ({ throwOnError = false, endSessionIfAnonymous = false }: SessionRefreshOptions = {}) => {
    if (!mounted.current || signedOut.current || logoutRequest.current) {
      if (throwOnError) throw new Error('Session refresh is unavailable');
      return;
    }
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setState(current => ({ ...current, error: null }));
    try {
      const user = await getCurrentUser({ signal: controller.signal });
      if (controller.signal.aborted && throwOnError) throw new Error('Session refresh was interrupted');
      if (!controller.signal.aborted) {
        signedOut.current = user === null && endSessionIfAnonymous;
        setState({ user, loading: false, error: null, signedOut: signedOut.current });
      }
    } catch (cause) {
      if (!controller.signal.aborted) {
        // A network error does not invalidate the last confirmed identity. A 401
        // is represented by a successful null response from the auth adapter.
        setState(current => ({ ...current, loading: false, error: getErrorMessage(cause, 'Failed to fetch user') }));
      }
      if (throwOnError) throw cause;
    }
  }, [getCurrentUser]);

  const logout = useCallback(() => {
    if (logoutRequest.current) return logoutRequest.current;
    if (signedOut.current) return Promise.resolve();
    const operation = Promise.resolve().then(endSession).then(() => {
      signedOut.current = true;
      request.current?.abort();
      if (mounted.current) setState({ user: null, loading: false, error: null, signedOut: true });
    }).finally(() => {
      logoutRequest.current = null;
      // An immediate logout can precede the initial read. If it fails, resume
      // that read so the session cannot remain in its initial loading state.
      if (mounted.current && !signedOut.current && !request.current) void refetch();
    });
    logoutRequest.current = operation;
    return operation;
  }, [endSession, refetch]);

  useEffect(() => {
    let disposed = false;
    mounted.current = true;
    void Promise.resolve().then(() => { if (!disposed) void refetch(); });
    return () => {
      disposed = true;
      mounted.current = false;
      request.current?.abort();
    };
  }, [refetch]);

  return { ...state, refetch, logout };
}
