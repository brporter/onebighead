import { useState, useId } from 'react';
import { useUser } from '../../contexts/useUser';
import { workspacesApi } from '../../api';
import { WorkspaceRole, type WorkspaceMembership } from '../../utils/types';

import './WorkspaceSwitcher.css';

export function WorkspaceSwitcher() {
  const { user, refetch } = useUser();
  const [isSwitching, setIsSwitching] = useState(false);
  const popoverId = useId();

  // Don't render if user has only one workspace
  if (!user || user.workspaces.length <= 1) {
    return null;
  }

  const activeWorkspace = user.activeWorkspace;
  const otherWorkspaces = user.workspaces.filter(t => t.workspaceId !== activeWorkspace.workspaceId);

  const handleSwitch = async (workspace: WorkspaceMembership) => {
    if (isSwitching) return;

    setIsSwitching(true);
    try {
      await workspacesApi.switch(workspace.workspaceId);
      // Reload the page to refresh all data for the new workspace context
      window.location.reload();
    } catch (error) {
      console.error('Failed to switch workspace:', error);
      setIsSwitching(false);
      await refetch();
    }
  };

  return (
    <div className="workspace-switcher">
      <button
        className="workspace-switcher__trigger"
        type="button"
        popoverTarget={popoverId}
        disabled={isSwitching}
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
            <span className="workspace-switcher__item-name">{activeWorkspace.workspaceName}</span>
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
                <span className="workspace-switcher__item-name">{workspace.workspaceName}</span>
                <span className="workspace-switcher__item-role">
                  {workspace.workspaceRole === WorkspaceRole.WorkspaceAdmin ? 'Admin' : 'Member'}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default WorkspaceSwitcher;
