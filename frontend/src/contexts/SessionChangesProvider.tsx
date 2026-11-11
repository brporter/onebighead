import { useState, useSyncExternalStore, type ReactNode } from 'react';
import { SessionChanges } from '../data/auth/SessionChanges';
import { SessionChangesContext } from './SessionChangesContext';
import { SessionChangeFeedback } from '../components/common/SessionChangeFeedback';

export function SessionChangesProvider({ children }: { children: ReactNode }) {
  const [changes] = useState(() => new SessionChanges());
  const state = useSyncExternalStore(changes.subscribe, changes.getSnapshot);
  return <SessionChangesContext value={changes}>
    <div inert={state.pending || state.recovery || state.leaving} className="session-change__content">{children}</div>
    <SessionChangeFeedback changes={changes} />
  </SessionChangesContext>;
}
