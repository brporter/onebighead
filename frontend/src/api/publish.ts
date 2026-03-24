/**
 * Publish/Unpublish API
 */
import { api } from './client';
import type {
  PublishResponse,
  BulkPublishResponse,
  UnpublishResponse,
  BulkUnpublishResponse,
  UnpublishPreviewResponse,
} from '../utils/types';

export const publishApi = {
  publishItem: (workspaceId: number, itemId: number) =>
    api.post<PublishResponse>(`/workspaces/${workspaceId}/items/${itemId}/publish`),

  unpublishItem: (workspaceId: number, itemId: number) =>
    api.post<UnpublishResponse>(`/workspaces/${workspaceId}/items/${itemId}/unpublish`),

  publishCategory: (workspaceId: number, categoryId: number, includeChildren: boolean) =>
    api.post<PublishResponse>(`/workspaces/${workspaceId}/categories/${categoryId}/publish`, { includeChildren }),

  unpublishCategory: (workspaceId: number, categoryId: number) =>
    api.post<UnpublishResponse>(`/workspaces/${workspaceId}/categories/${categoryId}/unpublish`),

  unpublishCategoryPreview: (workspaceId: number, categoryId: number) =>
    api.get<UnpublishPreviewResponse>(`/workspaces/${workspaceId}/categories/${categoryId}/unpublish-preview`),

  publishCollection: (workspaceId: number, collectionId: number, includeChildren: boolean) =>
    api.post<PublishResponse>(`/workspaces/${workspaceId}/collections/${collectionId}/publish`, { includeChildren }),

  unpublishCollection: (workspaceId: number, collectionId: number) =>
    api.post<UnpublishResponse>(`/workspaces/${workspaceId}/collections/${collectionId}/unpublish`),

  unpublishCollectionPreview: (workspaceId: number, collectionId: number) =>
    api.get<UnpublishPreviewResponse>(`/workspaces/${workspaceId}/collections/${collectionId}/unpublish-preview`),

  bulkPublish: (workspaceId: number, itemIds: number[]) =>
    api.post<BulkPublishResponse>(`/workspaces/${workspaceId}/items/bulk-publish`, { itemIds }),

  bulkUnpublish: (workspaceId: number, itemIds: number[]) =>
    api.post<BulkUnpublishResponse>(`/workspaces/${workspaceId}/items/bulk-unpublish`, { itemIds }),
};
