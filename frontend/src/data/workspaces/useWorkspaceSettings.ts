import { useCallback } from 'react';
import type { workspacesApi } from '../../api/workspaces';
import { useAsyncData } from '../../utils/useAsyncData';
import { useAsyncAction } from '../../utils/useAsyncAction';
import { runSessionMutation, type SessionMutationContext } from '../auth/runSessionMutation';

export type WorkspaceSettingsPort = Pick<typeof workspacesApi, 'getRestorableWorkspaces' | 'switch' | 'leave' | 'restoreWorkspace'>;

export function useWorkspaceSettings(gateway: WorkspaceSettingsPort, session: SessionMutationContext) {
  const fetchDeleted = useCallback((signal: AbortSignal) => gateway.getRestorableWorkspaces({ signal }), [gateway]);
  const deleted = useAsyncData(fetchDeleted);
  const action = useAsyncAction();

  const mutate = (operation: () => Promise<unknown>, message: string) => action.run(async () => {
    try {
      await runSessionMutation({
        changes: session.changes, kind: 'workspace', change: operation,
        confirmDiscard: session.confirmDiscard, failure: message, cancelled: 'Workspace change cancelled',
        refresh: async () => {
          await session.refresh();
          // An uncertain restore can still have committed. Refresh availability
          // after every confirmed session read, including read-only recovery.
          deleted.retry();
        },
      });
    } catch (cause) {
      if (session.changes.getSnapshot().recovery) throw new Error('Review your workspaces before trying again.');
      throw cause;
    }
  }, message);

  const change = (operation: () => Promise<{ success: boolean }>, message: string) => mutate(async () => {
    const result = await operation();
    if (!result.success) throw new Error(message);
  }, message);

  return {
    deleted,
    pending: action.pending,
    error: action.error,
    switchTo: (id: number) => change(() => gateway.switch(id), 'Failed to switch workspace'),
    leave: (id: number) => change(() => gateway.leave(id), 'Failed to leave workspace'),
    restore: (id: number) => mutate(() => gateway.restoreWorkspace(id), 'Failed to restore workspace'),
  };
}
