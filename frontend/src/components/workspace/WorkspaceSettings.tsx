import { useState } from 'react';
import { workspacesApi } from '../../api';
import { WorkspaceRole, type WorkspaceMembership } from '../../utils/types';
import { useWorkspaceSettings } from '../../data/workspaces/useWorkspaceSettings';
import { ContentState } from '../common/ContentState';
import WorkspaceSetupWizard from '../wizard/WorkspaceSetupWizard';
import WorkspaceEditModal from './WorkspaceEditModal';
import { WorkspaceDeletionSection } from './WorkspaceDeletionSection';
import { useUser } from '../../contexts/useUser';
import { useSessionChanges } from '../../data/auth/useSessionChanges';
import { useEditorStatus, type EditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import { SessionChangeFeedback } from '../common/SessionChangeFeedback';
import '../../styles/components/WorkspaceSettings.css';

interface WorkspaceSettingsProps {
  memberships: WorkspaceMembership[];
  activeWorkspaceId?: number;
  onCreated: () => void;
  onStatusChange?: EditorStatusListener;
}

export function WorkspaceSettings({ memberships, activeWorkspaceId, onCreated, onStatusChange }: WorkspaceSettingsProps) {
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<number | null>(null);
  const [deleting, setDeleting] = useState<number | null>(null);
  const [editorStatus, setEditorStatus] = useState<EditorStatus>({ dirty: false, pending: false });
  const { refetch } = useUser();
  const { changes, state, managed } = useSessionChanges();
  const actions = useWorkspaceSettings(workspacesApi, {
    changes,
    refresh: () => refetch({ throwOnError: true, endSessionIfAnonymous: true }),
    confirmDiscard: () => window.confirm('You have unsaved changes. Discard them?'),
  });
  const pending = actions.pending || state.pending || state.recovery || state.leaving || editorStatus.pending;
  useEditorStatus(editorStatus.dirty, pending, onStatusChange);
  const deleted = actions.deleted;
  const editedWorkspace = memberships.find(workspace => workspace.workspaceId === editing && workspace.workspaceRole === WorkspaceRole.WorkspaceAdmin);
  const deletedWorkspace = memberships.find(workspace => workspace.workspaceId === deleting && workspace.workspaceRole === WorkspaceRole.WorkspaceAdmin);

  if (creating) return <WorkspaceSetupWizard showTerms={false} isWelcome={false} onStatusChange={setEditorStatus}
    onComplete={() => { setCreating(false); onCreated(); }} onCancel={() => setCreating(false)} />;

  return <section className="settings-section">
    <div className="settings-section__header">
      <div>
        <h2 className="settings-section__title">My Workspaces</h2>
        <p className="settings-section__description">Manage your memberships and switch between workspaces.</p>
      </div>
      <button type="button" className="settings-section__addButton" disabled={pending} onClick={() => setCreating(true)}>+ Create New Workspace</button>
    </div>
    {pending && <p role="status">Updating workspace…</p>}
    {actions.error && <p className="settings-section__error" role="alert">{actions.error}</p>}
    {memberships.length === 0 && <ContentState kind="empty" title="No active workspaces">Create a workspace or restore one below to continue.</ContentState>}
    <div className="settings-workspace-list">
      {memberships.map(workspace => {
        const current = workspace.workspaceId === activeWorkspaceId;
        const admin = workspace.workspaceRole === WorkspaceRole.WorkspaceAdmin;
        return <article key={workspace.workspaceId} aria-label={workspace.workspaceName} className={`settings-workspace-card ${current ? 'settings-workspace-card--active' : ''}`}>
          <div className="settings-workspace-card__content">
            <div className="settings-workspace-card__header">
              <h3 className="settings-workspace-card__name">{workspace.workspaceName}</h3>
              {current && <span className="settings-workspace-card__badge settings-workspace-card__badge--current">Current</span>}
              <span className={`settings-workspace-card__badge ${admin ? 'settings-workspace-card__badge--admin' : ''}`}>{admin ? 'Admin' : 'Member'}</span>
            </div>
            {!workspace.hasCompletedWelcome && <p className="settings-workspace-card__status">Setup not completed</p>}
          </div>
          <div className="settings-workspace-card__actions">
            {admin && <button type="button" className="settings-workspace-card__button" aria-label={`Edit ${workspace.workspaceName}`} disabled={pending} onClick={() => setEditing(workspace.workspaceId)}>Edit</button>}
            {!current && <button type="button" className="settings-workspace-card__button" aria-label={`Switch to ${workspace.workspaceName}`} disabled={pending} onClick={() => { void actions.switchTo(workspace.workspaceId); }}>Switch</button>}
            {memberships.length > 1 && !admin && <button type="button" className="settings-workspace-card__button settings-workspace-card__button--danger" aria-label={`Leave ${workspace.workspaceName}`} disabled={pending} onClick={() => {
              if (window.confirm(`Are you sure you want to leave "${workspace.workspaceName}"? You will lose access to all data in this workspace.`)) void actions.leave(workspace.workspaceId);
            }}>Leave</button>}
            {admin && <button type="button" className="settings-workspace-card__button settings-workspace-card__button--danger"
              aria-label={`Delete ${workspace.workspaceName}`} disabled={pending} onClick={() => setDeleting(workspace.workspaceId)}>Delete</button>}
          </div>
        </article>;
      })}
    </div>
    <div className="settings-section__divider" />
    <h3 className="settings-section__subtitle">Recently Deleted Workspaces</h3>
    <p className="settings-section__description">Restore a workspace before its recovery period ends.</p>
    {deleted.loading && <ContentState kind="loading" title="Loading recoverable workspaces…" />}
    {deleted.error && <ContentState kind="error" title="Unable to load recoverable workspaces" action={<button type="button" className="content-state__button" onClick={deleted.retry}>Try again</button>}>{deleted.error}</ContentState>}
    {deleted.data && (deleted.data.length === 0
      ? <ContentState kind="empty" title="No workspaces to restore" />
      : <div className="settings-workspace-list">{deleted.data.map(workspace => <article key={workspace.workspaceId} aria-label={workspace.name} className="settings-workspace-card settings-workspace-card--deleted">
        <div className="settings-workspace-card__content">
          <h4 className="settings-workspace-card__name">{workspace.name}</h4>
          <p className="settings-workspace-card__stats">{workspace.stats.collectionCount} collections, {workspace.stats.itemCount} items</p>
          <p className="settings-workspace-card__countdown">{workspace.daysRemaining} days until permanent deletion</p>
        </div>
        <button type="button" className="settings-workspace-card__button settings-workspace-card__button--primary" aria-label={`Restore ${workspace.name}`} disabled={pending} onClick={() => { void actions.restore(workspace.workspaceId); }}>Restore</button>
      </article>)}</div>)}
    {editedWorkspace && <WorkspaceEditModal workspace={editedWorkspace} isOpen onClose={() => setEditing(null)}
      refresh={() => refetch({ throwOnError: true, endSessionIfAnonymous: true })} onStatusChange={setEditorStatus} />}
    {deletedWorkspace && <WorkspaceDeletionSection key={deletedWorkspace.workspaceId} workspace={deletedWorkspace}
      exportAvailable={deletedWorkspace.workspaceId === activeWorkspaceId} onClose={() => setDeleting(null)} onStatusChange={setEditorStatus}
      refresh={async () => { await refetch({ throwOnError: true, endSessionIfAnonymous: true }); deleted.retry(); }} />}
    {!managed && <SessionChangeFeedback changes={changes} />}
  </section>;
}
