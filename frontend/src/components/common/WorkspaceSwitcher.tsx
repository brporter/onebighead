import { useId } from 'react';
import { useUser } from '../../contexts/useUser';
import { workspacesApi } from '../../api';
import { WorkspaceRole, type WorkspaceMembership } from '../../utils/types';
import { useSessionChanges } from '../../data/auth/useSessionChanges';
import { SessionChangeFeedback } from './SessionChangeFeedback';

import './WorkspaceSwitcher.css';

// Keep header-owned feedback across the workspace boundary's remount.
const source = Symbol('workspace-switcher');

export function WorkspaceSwitcher() {
  const { user, refetch } = useUser();
  const { changes, state, managed } = useSessionChanges();
  const isSwitching = state.pending || state.recovery || state.leaving;
  const popoverId = useId();

  // Don't render if user has only one workspace
  if (!user || !user.activeWorkspace || user.workspaces.length <= 1) {
    return null;
  }

  const activeWorkspace = user.activeWorkspace;
  const otherWorkspaces = user.workspaces.filter(t => t.workspaceId !== activeWorkspace.workspaceId);

  const handleSwitch = async (workspace: WorkspaceMembership) => {
    await changes.run('workspace', async () => {
      const result = await workspacesApi.switch(workspace.workspaceId);
      if (!result.success) throw new Error('Unable to switch workspace');
    }, () => refetch({ throwOnError: true }), () => window.confirm('You have unsaved changes. Discard them?'), source);
  };

  return (
    <div className="workspace-switcher">
      <button
        className="workspace-switcher__trigger"
        type="button"
        popoverTarget={popoverId}
        disabled={isSwitching}
        aria-label={`Switch workspace: ${activeWorkspace.workspaceName}`}
      >
        <span className="workspace-switcher__name">{activeWorkspace.workspaceName}</span>
        <span className="workspace-switcher__icon" aria-hidden="true">
          ▾
        </span>
      </button>

      <div id={popoverId} popover="auto" className="workspace-switcher__dropdown">
        <div className="workspace-switcher__current">
          <span className="workspace-switcher__label">Current</span>
          <div className="workspace-switcher__item workspace-switcher__item--active">
            <span className="workspace-switcher__item-name">{activeWorkspace.workspaceName}</span>{' '}
            <span className="workspace-switcher__item-role">
              {activeWorkspace.workspaceRole === WorkspaceRole.WorkspaceAdmin ? 'Admin' : 'Member'}
            </span>
          </div>
        </div>

        {otherWorkspaces.length > 0 && (
          <div className="workspace-switcher__others">
            <span className="workspace-switcher__label">Switch to</span>
            {otherWorkspaces.map(workspace => (
              <button
                key={workspace.workspaceId}
                className="workspace-switcher__item"
                onClick={() => handleSwitch(workspace)}
                disabled={isSwitching}
                type="button"
              >
                <span className="workspace-switcher__item-name">{workspace.workspaceName}</span>{' '}
                <span className="workspace-switcher__item-role">
                  {workspace.workspaceRole === WorkspaceRole.WorkspaceAdmin ? 'Admin' : 'Member'}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>
      {state.source === source && state.error && !state.recovery && <p className="workspace-switcher__error" role="alert">{state.error}</p>}
      {!managed && <SessionChangeFeedback changes={changes} />}
    </div>
  );
}

export default WorkspaceSwitcher;
