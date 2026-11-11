import { useCallback } from 'react';
import type { adminApi } from '../../api/admin';
import { useAsyncData } from '../../utils/useAsyncData';
import { useAsyncAction } from '../../utils/useAsyncAction';

export type AdminUsersPort = Pick<typeof adminApi, 'getUsers' | 'deleteUser' | 'setAdminStatus'>;

export function useAdminUsers(query: string, { getUsers, deleteUser, setAdminStatus }: AdminUsersPort) {
  const fetcher = useCallback((signal: AbortSignal) => getUsers(query.trim() || undefined, { signal }), [getUsers, query]);
  const resource = useAsyncData(fetcher);
  const action = useAsyncAction();
  return { ...resource, pending: action.pending, actionError: action.error,
    remove: (id: number) => action.run(() => deleteUser(id), 'Unable to delete user', resource.retry),
    setAdministrator: (id: number, enabled: boolean) => action.run(() => setAdminStatus(id, enabled), 'Unable to update administrator status', resource.retry) };
}
