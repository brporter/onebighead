import { useCallback } from 'react';
import type { adminApi } from '../../api/admin';
import { useAsyncData } from '../../utils/useAsyncData';
import { useAsyncAction } from '../../utils/useAsyncAction';

export type AdminWorkspacesPort = Pick<typeof adminApi, 'getWorkspaces' | 'deleteWorkspace'>;

export function useAdminWorkspaces({ getWorkspaces, deleteWorkspace }: AdminWorkspacesPort) {
  const fetcher = useCallback((signal: AbortSignal) => getWorkspaces({ signal }), [getWorkspaces]);
  const resource = useAsyncData(fetcher);
  const action = useAsyncAction();
  return { ...resource, pending: action.pending, actionError: action.error,
    remove: (id: number) => action.run(() => deleteWorkspace(id), 'Unable to delete workspace', resource.retry) };
}
