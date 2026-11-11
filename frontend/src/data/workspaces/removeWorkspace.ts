import type { workspacesApi } from '../../api/workspaces';
import { runSessionMutation, type SessionMutationContext } from '../auth/runSessionMutation';

type WorkspaceRemovalPort = Pick<typeof workspacesApi, 'deleteWorkspace'>;

/** The server updates or clears the session cookie as part of deletion. */
export async function removeWorkspace(id: number, gateway: WorkspaceRemovalPort, session: SessionMutationContext): Promise<'signed-out' | 'changed'> {
  try {
    return await runSessionMutation({
      ...session, kind: 'workspace', failure: 'Failed to delete workspace', cancelled: 'Workspace deletion cancelled',
      change: async () => {
        const result = await gateway.deleteWorkspace(id);
        if (!result.success) throw new Error('Failed to delete workspace');
        return result.userSoftDeleted ? 'signed-out' : 'changed';
      },
    });
  } catch (cause) {
    if (session.changes.getSnapshot().recovery) throw new Error('Review deletion information before trying again.');
    throw cause;
  }
}
