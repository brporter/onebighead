export interface ItemProperty {
  category: string;
  name: string;
  value: string;
}

export interface ItemImage {
  url: string;
  alt: string;
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
}

export interface Category {
  tenantId: number;
  collectionId: number;
  categoryId: number;
  name: string;
  description: string;
  parentCategoryId: number | null;
  isSystem: boolean;
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
  isShared: boolean;
  isOwner: boolean;
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

