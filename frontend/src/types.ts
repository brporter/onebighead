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
  categoryId: number | null;
  name: string;
  summary: string;
  description: string;
  properties: ItemProperty[];
  images: ItemImage[];
}

export interface Category {
  tenantId: number;
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
  name: string;
  tenantId: number;
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

