export interface ItemProperty {
  category: string;
  name: string;
  value: string;
}

export interface ItemImage {
  url: string;
  alt: string;
}

/**
 * User's relationship with an item - whether they have it,
 * want it, or are willing to trade/sell it.
 *
 * Note: Uses string values to match backend JsonStringEnumConverter serialization.
 */
export enum UserFlag {
  None = "None",
  Have = "Have",
  Want = "Want",
  TradeOrSell = "TradeOrSell",
}

/**
 * Visibility setting for collections, categories, and items.
 *
 * Note: Uses string values to match backend JsonStringEnumConverter serialization.
 */
export enum Visibility {
  Default = "Default",  // Inherit from parent
  Private = "Private",  // Explicitly private
  Public = "Public",    // Explicitly public (if parent allows)
}

export interface Item {
  id: number | null;
  tenantId: number;
  collectionId: number;
  categoryId: number | null;
  name: string;
  summary: string;
  description: string;
  properties: ItemProperty[];
  images: ItemImage[];
  visibility: Visibility;
  effectiveIsPublic: boolean;
  userFlag: UserFlag;
}

export interface Category {
  tenantId: number;
  collectionId: number;
  categoryId: number;
  name: string;
  description: string;
  parentCategoryId: number | null;
  isSystem: boolean;
  visibility: Visibility;
  effectiveIsPublic: boolean;
  itemTemplateIds: number[];
}

export interface CategoryNode extends Category {
  children: CategoryNode[];
}

export interface Collection {
  collectionId: number;
  tenantId: number;
  name: string;
  description: string;
  heroImageUrl: string | null;
  slug: string;
  visibility: Visibility;
  effectiveIsPublic: boolean;
}

export interface Tenant {
  tenantId: number;
  name: string;
  owner: string;
}

export interface CurrentUser {
  userId: number;
  email: string;
  tenantId: number;
  tenantName: string;
  hasCompletedWelcome: boolean;
  isSystemAdministrator: boolean;
}

export interface TenantSummary {
  tenantId: number;
  name: string;
  userCount: number;
  collectionCount: number;
  itemCount: number;
  imageCount: number;
  createdAt: string;
}

export interface UserSummary {
  userId: number;
  email: string;
  tenantId: number;
  tenantName: string;
  identityProvider: string;
  isSystemAdministrator: boolean;
  createdAt: string;
}

export interface ItemTemplateProperty {
  itemTemplatePropertyId?: number;
  category: string;
  name: string;
}

export interface ItemTemplate {
  itemTemplateId: number;
  name: string;
  description: string;
  isSystem: boolean;
  properties: ItemTemplateProperty[];
  createdAt: string;
  updatedAt: string;
}

export interface CreateItemTemplateRequest {
  name: string;
  description: string;
  properties: Omit<ItemTemplateProperty, 'itemTemplatePropertyId'>[];
}

export interface UpdateItemTemplateRequest {
  name: string;
  description: string;
  properties: Omit<ItemTemplateProperty, 'itemTemplatePropertyId'>[];
}

export interface ThemeCategory {
  name: string;
  description: string;
  parentName: string | null;
  sortOrder: number;
}

export interface ThemeTemplate {
  itemTemplateId: number;
  name: string;
  description: string;
  properties: ItemTemplateProperty[];
}

export interface CollectionTheme {
  themeId: number;
  name: string;
  description: string;
  iconName: string;
  sortOrder: number;
  templates: ThemeTemplate[];
  categories: ThemeCategory[];
}

export interface SetupCollectionRequest {
  name: string;
  description?: string;
  heroImageUrl?: string;
  visibility?: Visibility;
  themeId: number;
}

