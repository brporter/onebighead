import { useSyncExternalStore } from 'react';
import type { SessionChanges } from '../../data/auth/SessionChanges';
import { ModalDialog } from './ModalDialog';
import '../../styles/components/SessionChangeFeedback.css';

export function SessionChangeFeedback({ changes }: { changes: SessionChanges }) {
  const state = useSyncExternalStore(changes.subscribe, changes.getSnapshot);
  if (!state.pending && !state.recovery) return null;
  return <ModalDialog label="Updating your session" onClose={() => {}}>
    <section className="modal session-change">
      <h2>Updating your session</h2>
      {state.pending ? <p role="status">Please wait while we confirm your session.</p> : <>
        <p className="session-change__error" role="alert">{state.error}</p>
        <p>Your session could not be confirmed. Refresh it before continuing.</p>
        <button className="modal__button modal__button--primary" type="button" onClick={() => void changes.retryRefresh()}>Retry session refresh</button>
      </>}
    </section>
  </ModalDialog>;
}
