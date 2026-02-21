import { ReactNode } from 'react';
import { vi } from 'vitest';
import type { Category, Item, Collection } from '../../src/utils/types';
import type { DataContextValue } from '../../src/contexts/DataContext';
import { Visibility, UserFlag } from '../../src/utils/types';

export const mockCategories: Category[] = [
  { workspaceId: 1, categoryId: 1, collectionId: 1, name: 'Root Category', description: 'Root description', parentCategoryId: null, isSystem: false, visibility: Visibility.Default, effectiveIsPublic: false, itemTemplateIds: [] },
  { workspaceId: 1, categoryId: 2, collectionId: 1, name: 'Child Category', description: 'Child description', parentCategoryId: 1, isSystem: false, visibility: Visibility.Default, effectiveIsPublic: false, itemTemplateIds: [] },
  { workspaceId: 1, categoryId: 3, collectionId: 1, name: 'Another Root', description: 'Another root description', parentCategoryId: null, isSystem: false, visibility: Visibility.Default, effectiveIsPublic: false, itemTemplateIds: [] },
];

export const mockItems: Item[] = [
  {
    id: 1,
    workspaceId: 1,
    collectionId: 1,
    categoryId: 2,
    templateKey: null,
    name: 'Test Item 1',
    summary: 'Test summary 1',
    description: 'Test description 1',
    properties: [{ category: 'General', name: 'Prop1', value: 'Value1' }],
    images: [{ url: 'https://example.com/image1.jpg', alt: 'Image 1' }],
    visibility: Visibility.Default,
    effectiveIsPublic: false,
    userFlag: UserFlag.Have,
  },
  {
    id: 2,
    workspaceId: 1,
    collectionId: 1,
    categoryId: 2,
    templateKey: null,
    name: 'Test Item 2',
    summary: 'Test summary 2',
    description: 'Test description 2',
    properties: [],
    images: [],
    visibility: Visibility.Default,
    effectiveIsPublic: false,
    userFlag: UserFlag.Have,
  },
];

export const mockCollections: Collection[] = [
  { collectionId: 1, name: 'Test Collection', workspaceId: 1, description: '', heroImageUrl: null, slug: 'test-collection', visibility: Visibility.Private, effectiveIsPublic: false },
];

export const createMockDataContext = (overrides?: Partial<DataContextValue>): DataContextValue => ({
  // Current collection
  currentCollection: mockCollections[0],
  setCurrentCollection: vi.fn(),

  // Collections
  collections: mockCollections,
  collectionsLoading: false,
  collectionsError: null,
  loadCollections: vi.fn(async () => {}),
  addCollection: vi.fn(async () => mockCollections[0]),
  setupCollection: vi.fn(async () => mockCollections[0]),
  updateCollection: vi.fn(async () => {}),
  deleteCollection: vi.fn(async () => {}),

  // Themes
  themes: [],
  themesLoading: false,
  themesError: null,
  loadThemes: vi.fn(async () => {}),

  // Categories
  categories: mockCategories,
  categoriesLoading: false,
  categoriesError: null,
  loadCategoriesForCollection: vi.fn(async () => {}),
  addCategory: vi.fn(async () => 4),
  updateCategory: vi.fn(async () => {}),
  deleteCategory: vi.fn(async () => {}),
  getCategoryTemplates: vi.fn(async () => []),

  // Items
  items: mockItems,
  itemsLoading: false,
  itemsError: null,
  loadItemsForCategory: vi.fn(async () => {}),
  loadItemById: vi.fn(async () => null),
  addItem: vi.fn(async () => 3),
  updateItem: vi.fn(async () => {}),
  deleteItem: vi.fn(async () => {}),

  // Image upload
  uploadImage: vi.fn(async () => ({ key: 'test-key', url: 'https://example.com/image.jpg' })),

  // Property suggestions
  propertyCategorySuggestions: [],
  propertyNameSuggestions: [],
  loadPropertySuggestions: vi.fn(async () => {}),
  syncPropertySuggestions: vi.fn(async () => {}),
  addLocalCategorySuggestion: vi.fn(),
  addLocalNameSuggestion: vi.fn(),

  // Item templates
  itemTemplates: [],
  itemTemplatesLoading: false,
  itemTemplatesError: null,
  loadItemTemplates: vi.fn(async () => {}),
  loadCollectionTemplates: vi.fn(async () => []),
  createItemTemplate: vi.fn(async () => ({ itemTemplateId: 1, templateKey: 'a1b2c3d4-0000-4000-8000-000000000000', name: 'Test', description: '', isSystem: false, properties: [], createdAt: '', updatedAt: '' })),
  updateItemTemplate: vi.fn(async () => ({ itemTemplateId: 1, templateKey: 'a1b2c3d4-0000-4000-8000-000000000000', name: 'Test', description: '', isSystem: false, properties: [], createdAt: '', updatedAt: '' })),
  deleteItemTemplate: vi.fn(async () => {}),
  associateTemplateWithCollection: vi.fn(async () => {}),
  disassociateTemplateFromCollection: vi.fn(async () => {}),

  // Category tree UI state
  expandedCategoryIds: new Set([1, 3]), // Root categories expanded by default
  toggleCategoryExpanded: vi.fn(),

  ...overrides,
});

export const mockDataContextValue = createMockDataContext();

// Mock the DataContext module
vi.mock('../../src/contexts/DataContext', async () => {
  const actual = await vi.importActual<typeof import('../../src/contexts/DataContext')>('../../src/contexts/DataContext');
  return {
    ...actual,
    useData: vi.fn(() => mockDataContextValue),
    DataProvider: ({ children }: { children: ReactNode }) => children,
  };
});

