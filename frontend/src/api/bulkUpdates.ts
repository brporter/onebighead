/**
 * Bulk Updates API
 */
import { api, type RequestOptions } from './client';

export interface PropertyIdentifierDto {
  category: string;
  name: string;
}

export interface PropertyRenameMappingDto {
  oldCategory: string;
  oldName: string;
  newCategory: string;
  newName: string;
}

export interface EnqueueBulkUpdateRequest {
  scope: string;
  templateKey?: string;
  categoryId?: number;
  collectionId?: number;
  excludeItemId?: number;
  oldProperties: PropertyIdentifierDto[];
  newProperties: PropertyIdentifierDto[];
  renameMappings?: PropertyRenameMappingDto[];
}

export interface BulkUpdatePreviewRequest {
  scope: string;
  templateKey?: string;
  categoryId?: number;
  collectionId?: number;
  excludeItemId?: number;
}

export interface BulkUpdatePreviewResponse {
  affectedItemCount: number;
}

export interface BulkUpdateJobResponse {
  jobId: string;
  status: string;
  totalItems: number;
  processedItems: number;
  failedItems: number;
  errorMessage?: string;
}

export const bulkUpdatesApi = {
  preview(request: BulkUpdatePreviewRequest, options?: RequestOptions): Promise<BulkUpdatePreviewResponse> {
    return api.post<BulkUpdatePreviewResponse>('/bulkupdates/preview', request, options);
  },

  enqueue(request: EnqueueBulkUpdateRequest, options?: RequestOptions): Promise<BulkUpdateJobResponse> {
    return api.post<BulkUpdateJobResponse>('/bulkupdates', request, options);
  },

  getStatus(jobId: string, options?: RequestOptions): Promise<BulkUpdateJobResponse> {
    return api.get<BulkUpdateJobResponse>(`/bulkupdates/${jobId}`, options);
  },

  getCollectionStatus(collectionId: number, options?: RequestOptions): Promise<BulkUpdateJobResponse | null> {
    return api.get<BulkUpdateJobResponse | null>(`/bulkupdates/collection/${collectionId}/status`, options);
  },
};
