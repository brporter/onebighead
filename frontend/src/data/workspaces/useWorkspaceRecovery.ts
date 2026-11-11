import { useCallback, useState } from 'react';
import type { workspacesApi } from '../../api/workspaces';
import { useAsyncData } from '../../utils/useAsyncData';
import { useAsyncAction } from '../../utils/useAsyncAction';

export type WorkspaceRecoveryPort = Pick<typeof workspacesApi, 'getRestorableWorkspaces' | 'restoreWorkspaces'>;

/** Owns one user's recovery session, including confirmed-restore refresh retries. */
export function useWorkspaceRecovery(needed: boolean, gateway: WorkspaceRecoveryPort, refresh: () => Promise<void>, onComplete: () => void) {
  const action = useAsyncAction();
  const read = useCallback((signal: AbortSignal) => gateway.getRestorableWorkspaces({ signal }), [gateway]);
  // Refresh may add memberships before the completion callback runs. Keep the
  // recovery session and its list intact until that action has finished.
  const recovery = useAsyncData(needed || action.pending ? read : null);
  const [selection, setSelection] = useState<number[] | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const workspaces = recovery.data ?? [];
  const selectedIds = selection === null
    ? workspaces.slice(0, 1).map(workspace => workspace.workspaceId)
    : selection.filter(id => workspaces.some(workspace => workspace.workspaceId === id));

  function toggle(id: number) {
    setSelection(selectedIds.includes(id) ? selectedIds.filter(selected => selected !== id) : [...selectedIds, id]);
  }

  const restore = () => action.run(async () => {
    if (!confirmed) {
      if (selectedIds.length === 0) throw new Error('Select at least one workspace to restore');
      const result = await gateway.restoreWorkspaces({ workspaceIds: selectedIds });
      if (result.activeWorkspaceId <= 0) throw new Error('No workspace was restored. Reload the recovery list to check its availability.');
      setConfirmed(true);
    }
    await refresh();
  }, 'Unable to restore workspaces', onComplete);

  return { recovery, workspaces, selectedIds, toggle, restore, confirmed, pending: action.pending, error: action.error };
}
