/**
 * Centralized API module
 *
 * Usage:
 *   import { collectionsApi, itemsApi, api } from './api';
 *
 *   // Use typed API methods
 *   const collections = await collectionsApi.getAll();
 *   const item = await itemsApi.getById(123);
 *
 *   // Or use the raw client for custom requests
 *   const data = await api.get<CustomType>('/custom/endpoint');
 */

export { api, ApiError, type RequestOptions } from './client';
export { dashboardApi, type DashboardData, type DailyView } from './dashboard';
export { collectionsApi, type CreateCollectionRequest, type UpdateCollectionRequest } from './collections';
export { categoriesApi, type CreateCategoryRequest, type UpdateCategoryRequest } from './categories';
export { itemsApi, type GetItemsOptions, type GetItemsResult } from './items';
export { imagesApi, type UploadImageResult } from './images';
export { templatesApi, type TemplateFilter } from './templates';
export { suggestionsApi, type PropertySuggestionsResponse } from './suggestions';
export { authApi } from './auth';
export { adminApi } from './admin';
export { exportApi } from './export';
export { themesApi } from './themes';
export { usersApi } from './users';
export { bulkUpdatesApi, type BulkUpdateJobResponse, type PropertyIdentifierDto, type PropertyRenameMappingDto, type EnqueueBulkUpdateRequest, type BulkUpdatePreviewRequest, type BulkUpdatePreviewResponse } from './bulkUpdates';
export { workspacesApi, type CreateWorkspaceRequest, type CreateWorkspaceResponse, type SwitchWorkspaceResponse, type LeaveWorkspaceResponse, type WorkspaceStats, type WorkspaceDeletionResponse, type TransferAdminRequest, type TransferAdminResponse, type UpdatePublicAccessRequest, type UpdatePublicAccessResponse, type CheckSlugResponse } from './workspaces';
export { accountApi, type UserDeletionInfo, type WorkspaceMembershipDeletionInfo, type DeleteAccountRequest, type DeleteAccountResponse, WorkspaceActionType, DeletionBlockerReason } from './account';
export * from './support';
export { publicApi, type PublicWorkspace, type PublicCollection, type PublicCollectionDetail, type PublicCategory, type PublicItemSummary, type PublicItem, type PublicItemProperty, type PublicItemImage } from './public';
export { publishApi } from './publish';
