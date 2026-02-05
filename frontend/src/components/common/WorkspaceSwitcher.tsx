import { useState, useRef, useEffect } from 'react';
import { useUser } from '../../contexts/UserContext';
import { workspacesApi } from '../../api';
import type { WorkspaceMembership } from '../../utils/types';

import './WorkspaceSwitcher.css';

export function WorkspaceSwitcher() {
  const { user, refetch } = useUser();
  const [isOpen, setIsOpen] = useState(false);
  const [isSwitching, setIsSwitching] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [isOpen]);

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
    <div className="workspace-switcher" ref={dropdownRef}>
      <button
        className="workspace-switcher__trigger"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-haspopup="listbox"
        disabled={isSwitching}
      >
        <span className="workspace-switcher__name">{activeWorkspace.workspaceName}</span>
        <span className="workspace-switcher__icon" aria-hidden="true">
          {isOpen ? '\u25B2' : '\u25BC'}
        </span>
      </button>

      {isOpen && (
        <div className="workspace-switcher__dropdown" role="listbox">
          <div className="workspace-switcher__current">
            <span className="workspace-switcher__label">Current</span>
            <div className="workspace-switcher__item workspace-switcher__item--active">
              <span className="workspace-switcher__item-name">{activeWorkspace.workspaceName}</span>
              <span className="workspace-switcher__item-role">
                {activeWorkspace.workspaceRole === 'WorkspaceAdmin' ? 'Admin' : 'Member'}
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
                  role="option"
                >
                  <span className="workspace-switcher__item-name">{workspace.workspaceName}</span>
                  <span className="workspace-switcher__item-role">
                    {workspace.workspaceRole === 'WorkspaceAdmin' ? 'Admin' : 'Member'}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default WorkspaceSwitcher;
