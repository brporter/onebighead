import { api } from './client';
import type { PreflightResponse, ExecuteRequest, ExecuteResponse, EntityRef } from '../utils/types';

export const publishManagerApi = {
  preflight(workspaceId: number, action: 'publish' | 'unpublish', entities: EntityRef[]): Promise<PreflightResponse> {
    return api.post<PreflightResponse>(`/workspaces/${workspaceId}/publish/preflight`, { action, entities });
  },

  execute(workspaceId: number, request: ExecuteRequest): Promise<ExecuteResponse> {
    return api.post<ExecuteResponse>(`/workspaces/${workspaceId}/publish/execute`, request);
  },
};
