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
export { tenantsApi, type CreateTenantRequest, type CreateTenantResponse, type SwitchTenantResponse, type LeaveTenantResponse, type TenantStats, type TenantDeletionResponse, type TransferAdminRequest, type TransferAdminResponse } from './tenants';
export { accountApi, type UserDeletionInfo, type TenantMembershipDeletionInfo, type DeleteAccountRequest, type DeleteAccountResponse, TenantActionType, DeletionBlockerReason } from './account';
export * from './support';
