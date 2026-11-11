import type { PropertyIdentifierDto } from '../../api/bulkUpdates';

export interface ScopeOption {
  scope: string;
  label: string;
  count: number;
  templateKey?: string;
  categoryId?: number;
  collectionId?: number;
}

export interface ItemPropertyChangeOffer {
  scopeOptions: ScopeOption[];
  oldProperties: PropertyIdentifierDto[];
  newProperties: PropertyIdentifierDto[];
  excludeItemId: number;
}
