import { useContext, useLayoutEffect, useState, useSyncExternalStore } from 'react';
import { SessionChangesContext } from '../../contexts/SessionChangesContext';
import { SessionChanges } from './SessionChanges';

/** Standalone controls get an isolated coordinator; UserProvider supplies the shared one. */
export function useSessionChanges() {
  const shared = useContext(SessionChangesContext);
  const [local] = useState(() => new SessionChanges());
  const changes = shared ?? local;
  const state = useSyncExternalStore(changes.subscribe, changes.getSnapshot);
  return { changes, state, managed: shared !== null };
}

export function useSessionProtection(dirty: boolean, pending: boolean) {
  const changes = useContext(SessionChangesContext);
  useLayoutEffect(() => changes?.protect({ dirty, pending }), [changes, dirty, pending]);
  return changes;
}
