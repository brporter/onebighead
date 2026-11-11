import { useCallback } from 'react';
import type { adminApi } from '../../api/admin';
import { useAsyncData } from '../../utils/useAsyncData';
import { useAsyncAction } from '../../utils/useAsyncAction';

export type AdminTemplatesPort = Pick<typeof adminApi, 'getSystemTemplates' | 'deleteSystemTemplate' | 'createSystemTemplate' | 'updateSystemTemplate'>;

export function useAdminTemplates({ getSystemTemplates, deleteSystemTemplate }: Pick<AdminTemplatesPort, 'getSystemTemplates' | 'deleteSystemTemplate'>) {
  const fetcher = useCallback((signal: AbortSignal) => getSystemTemplates({ signal }), [getSystemTemplates]);
  const resource = useAsyncData(fetcher);
  const action = useAsyncAction();
  return { ...resource, pending: action.pending, actionError: action.error,
    remove: (id: number) => action.run(() => deleteSystemTemplate(id), 'Unable to delete system template', resource.retry) };
}
