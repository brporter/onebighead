import type { collectionsApi } from '../api/collections';
import type { categoriesApi } from '../api/categories';
import type { itemsApi } from '../api/items';
import type { templatesApi } from '../api/templates';
import type { suggestionsApi } from '../api/suggestions';
import type { themesApi } from '../api/themes';

// Structural ports: state modules receive only the operations they need.
// HTTP adapters and in-memory test doubles implement the same contracts.
export type CollectionGateway = Pick<typeof collectionsApi, 'getAll' | 'create' | 'setup' | 'update' | 'delete'>;
export type CategoryGateway = Pick<typeof categoriesApi, 'getAll' | 'create' | 'update' | 'delete' | 'reorder' | 'getTemplates'>;
export type ItemGateway = Pick<typeof itemsApi, 'getAll' | 'getById' | 'create' | 'update' | 'delete'>;
export type TemplateGateway = Pick<typeof templatesApi, 'getAll' | 'getForCollection' | 'create' | 'update' | 'delete' | 'associateWithCollection' | 'disassociateFromCollection'>;
export type SuggestionGateway = typeof suggestionsApi;
export type ThemeGateway = Pick<typeof themesApi, 'getAll'>;
