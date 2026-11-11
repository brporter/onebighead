import { useCallback, useEffect, useRef } from 'react';
import { useBlocker } from 'react-router-dom';
import { useSessionProtection } from '../auth/useSessionChanges';

/** Protects drafts during SPA history changes and full-page navigations. */
export function useUnsavedNavigation(dirty: boolean, pending: boolean) {
  const session = useSessionProtection(dirty, pending);
  const completing = useRef(false);
  const blocker = useBlocker(({ currentLocation, nextLocation }) =>
    !completing.current && (dirty || pending) && (currentLocation.pathname !== nextLocation.pathname || currentLocation.search !== nextLocation.search));

  // A successful mutation or confirmed discard may navigate before React commits
  // the cleared editor state. Limit that permission to this synchronous callback.
  const completeNavigation = useCallback((navigate: () => void) => {
    completing.current = true;
    try { navigate(); } finally { completing.current = false; }
  }, []);

  useEffect(() => {
    if (blocker.state !== 'blocked') return;
    if (!pending && window.confirm('You have unsaved changes. Discard them?')) blocker.proceed();
    else blocker.reset();
  }, [blocker, pending]);

  useEffect(() => {
    if (!dirty && !pending) return;
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (session?.getSnapshot().leaving) return;
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', beforeUnload);
    return () => window.removeEventListener('beforeunload', beforeUnload);
  }, [dirty, pending, session]);

  return completeNavigation;
}
