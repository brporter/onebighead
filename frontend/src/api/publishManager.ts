import { api, type RequestOptions } from './client';
import type { PreflightResponse, ExecuteRequest, ExecuteResponse, EntityRef } from '../utils/types';

export const publishManagerApi = {
  preflight(workspaceId: number, action: 'publish' | 'unpublish', entities: EntityRef[], options?: RequestOptions): Promise<PreflightResponse> {
    return api.post<PreflightResponse>(`/workspaces/${workspaceId}/publish/preflight`, { action, entities }, options);
  },

  execute(workspaceId: number, request: ExecuteRequest, options?: RequestOptions): Promise<ExecuteResponse> {
    return api.post<ExecuteResponse>(`/workspaces/${workspaceId}/publish/execute`, request, options);
  },
};
