import { useState, useEffect } from 'react';
import { workspacesApi } from '../../api';
import type { RestorableWorkspace } from '../../api/workspaces';
import '../../styles/components/WorkspaceRestorationModal.css';

interface WorkspaceRestorationModalProps {
  isOpen: boolean;
  onRestoreComplete: () => void;
  onCreateNew: () => void;
}

export function WorkspaceRestorationModal({
  isOpen,
  onRestoreComplete,
  onCreateNew
}: WorkspaceRestorationModalProps) {
  const [restorableWorkspaces, setRestorableWorkspaces] = useState<RestorableWorkspace[]>([]);
  const [selectedWorkspaceIds, setSelectedWorkspaceIds] = useState<Set<number>>(new Set());
  const [choice, setChoice] = useState<'restore' | 'create'>('restore');
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      loadRestorableWorkspaces();
    }
  }, [isOpen]);

  const loadRestorableWorkspaces = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const workspaces = await workspacesApi.getRestorableWorkspaces();
      setRestorableWorkspaces(workspaces);
      if (workspaces.length > 0) {
        setSelectedWorkspaceIds(new Set([workspaces[0].workspaceId]));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load workspaces');
    } finally {
      setIsLoading(false);
    }
  };

  const toggleWorkspace = (workspaceId: number) => {
    const newSet = new Set(selectedWorkspaceIds);
    if (newSet.has(workspaceId)) {
      newSet.delete(workspaceId);
    } else {
      newSet.add(workspaceId);
    }
    setSelectedWorkspaceIds(newSet);
  };

  const handleContinue = async () => {
    if (choice === 'create') {
      onCreateNew();
      return;
    }

    if (selectedWorkspaceIds.size === 0) {
      setError('Please select at least one workspace to restore');
      return;
    }

    setIsSubmitting(true);
    setError(null);
    try {
      await workspacesApi.restoreWorkspaces({
        workspaceIds: Array.from(selectedWorkspaceIds)
      });
      onRestoreComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to restore workspaces');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!isOpen) return null;

  console.log('[WorkspaceRestorationModal] Rendering modal, isLoading:', isLoading, 'workspaces:', restorableWorkspaces.length);

  return (
    <div className="restoration-modal-overlay">
      <div className="restoration-modal">
        <h2 className="restoration-modal__title">Welcome Back</h2>
        <p className="restoration-modal__description">
          Your account has been restored. Choose how you'd like to continue:
        </p>

        {error && <div className="restoration-modal__error">{error}</div>}

        {isLoading ? (
          <div className="restoration-modal__loading">Loading...</div>
        ) : (
          <>
            <div className="restoration-modal__options">
              <label className="restoration-modal__option">
                <input
                  type="radio"
                  name="choice"
                  checked={choice === 'restore'}
                  onChange={() => setChoice('restore')}
                />
                <span>Restore existing workspace(s)</span>
              </label>

              {choice === 'restore' && restorableWorkspaces.length > 0 && (
                <div className="restoration-modal__workspaces">
                  {restorableWorkspaces.map(workspace => (
                    <label key={workspace.workspaceId} className="restoration-modal__workspace">
                      <input
                        type="checkbox"
                        checked={selectedWorkspaceIds.has(workspace.workspaceId)}
                        onChange={() => toggleWorkspace(workspace.workspaceId)}
                      />
                      <div className="restoration-modal__workspace-info">
                        <span className="restoration-modal__workspace-name">{workspace.name}</span>
                        <span className="restoration-modal__workspace-stats">
                          {workspace.stats.collectionCount} collections, {workspace.stats.itemCount} items
                        </span>
                        <span className="restoration-modal__workspace-countdown">
                          {workspace.daysRemaining} days until permanent deletion
                        </span>
                      </div>
                    </label>
                  ))}
                </div>
              )}

              <label className="restoration-modal__option">
                <input
                  type="radio"
                  name="choice"
                  checked={choice === 'create'}
                  onChange={() => setChoice('create')}
                />
                <span>Create a new workspace</span>
              </label>
            </div>

            <button
              className="restoration-modal__button"
              onClick={handleContinue}
              disabled={isSubmitting || (choice === 'restore' && selectedWorkspaceIds.size === 0)}
            >
              {isSubmitting ? 'Processing...' : 'Continue'}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

export default WorkspaceRestorationModal;
