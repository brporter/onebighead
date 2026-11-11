import type { SessionChanges } from '../auth/SessionChanges';
import type { AdminUsersPort } from './useAdminUsers';
import type { AdminWorkspacesPort } from './useAdminWorkspaces';
import { runSessionMutation } from '../auth/runSessionMutation';

export type AdministratorSessionPort = AdminUsersPort & AdminWorkspacesPort;

/** Account/workspace writes may affect the acting administrator, even after a lost response. */
export function createAdministratorSessionGateway(
  gateway: AdministratorSessionPort,
  changes: SessionChanges,
  refresh: () => Promise<void>,
  confirmDiscard: () => boolean,
): AdministratorSessionPort {
  const mutate = <T>(change: () => Promise<T>, failure: string, cancelled: string) =>
    runSessionMutation({ changes, kind: 'account', change, refresh, confirmDiscard, failure, cancelled });

  return {
    getWorkspaces: gateway.getWorkspaces,
    getUsers: gateway.getUsers,
    deleteWorkspace: id => mutate(() => gateway.deleteWorkspace(id), 'Unable to delete workspace', 'Workspace deletion cancelled'),
    deleteUser: id => mutate(() => gateway.deleteUser(id), 'Unable to delete user', 'Account deletion cancelled'),
    setAdminStatus: (id, enabled) => mutate(() => gateway.setAdminStatus(id, enabled), 'Unable to update administrator status', 'Administrator change cancelled'),
  };
}
