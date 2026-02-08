/**
 * Bulk Updates API
 */
import { api } from './client';

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
  preview(request: BulkUpdatePreviewRequest): Promise<BulkUpdatePreviewResponse> {
    return api.post<BulkUpdatePreviewResponse>('/bulkupdates/preview', request);
  },

  enqueue(request: EnqueueBulkUpdateRequest): Promise<BulkUpdateJobResponse> {
    return api.post<BulkUpdateJobResponse>('/bulkupdates', request);
  },

  getStatus(jobId: string): Promise<BulkUpdateJobResponse> {
    return api.get<BulkUpdateJobResponse>(`/bulkupdates/${jobId}`);
  },

  getCollectionStatus(collectionId: number): Promise<BulkUpdateJobResponse | null> {
    return api.get<BulkUpdateJobResponse | null>(`/bulkupdates/collection/${collectionId}/status`);
  },
};
