import { useId } from 'react';
import type { RestorableWorkspace } from '../../api/workspaces';
import { ModalDialog } from '../common/ModalDialog';
import '../../styles/components/WorkspaceRestorationModal.css';

interface WorkspaceRestorationModalProps {
  workspaces: RestorableWorkspace[];
  selectedIds: number[];
  toggle: (id: number) => void;
  restore: () => Promise<void>;
  confirmed: boolean;
  pending: boolean;
  error: string | null;
  onCreateNew: () => void;
  onReload: () => void;
}

/** Recovery choices are explicit; Escape/backdrop cannot reveal workspace routes. */
export function WorkspaceRestorationModal({ workspaces, selectedIds, toggle, restore, confirmed, pending, error, onCreateNew, onReload }: WorkspaceRestorationModalProps) {
  const id = useId();
  const locked = pending || confirmed;
  return <ModalDialog label="Restore workspace" onClose={() => {}}>
    <section className="restoration-modal" aria-labelledby={`${id}-title`} aria-busy={pending}>
      <h2 id={`${id}-title`} className="restoration-modal__title">Welcome Back</h2>
      <p className="restoration-modal__description">Choose the workspaces you'd like to restore, or start with a new workspace.</p>
      {error && <div className="restoration-modal__error" role="alert">{error}</div>}
      {confirmed && <p role="status">Your workspaces have been restored. Continue to refresh your session.</p>}
      <fieldset className="restoration-modal__fields" disabled={locked}>
        <legend>Workspaces to restore</legend>
        <div className="restoration-modal__workspaces">
          {workspaces.map(workspace => <label key={workspace.workspaceId} className="restoration-modal__workspace">
            <input type="checkbox" checked={selectedIds.includes(workspace.workspaceId)} onChange={() => toggle(workspace.workspaceId)} />
            <span className="restoration-modal__workspace-info">
              <span className="restoration-modal__workspace-name">{workspace.name}</span>
              <span className="restoration-modal__workspace-stats">{workspace.stats.collectionCount} collections, {workspace.stats.itemCount} items</span>
              <span className="restoration-modal__workspace-countdown">{workspace.daysRemaining} days until permanent deletion</span>
            </span>
          </label>)}
        </div>
      </fieldset>
      <div className="restoration-modal__actions">
        <button type="button" className="restoration-modal__button" disabled={pending || (!confirmed && selectedIds.length === 0)} onClick={() => { void restore(); }}>
          {pending ? confirmed ? 'Refreshing session…' : 'Restoring…' : confirmed ? 'Continue to workspace' : 'Restore selected workspaces'}
        </button>
        <button type="button" className="restoration-modal__button restoration-modal__button--secondary" disabled={locked} onClick={onCreateNew}>Create a new workspace</button>
        {error && !confirmed && <button type="button" className="restoration-modal__button restoration-modal__button--secondary" disabled={pending} onClick={onReload}>Reload recovery list</button>}
      </div>
    </section>
  </ModalDialog>;
}

export default WorkspaceRestorationModal;
