/**
 * Test factories for creating properly typed mock objects.
 * Use these to ensure all required properties are present in test mocks.
 */
import type {
  Item,
  Category,
  Collection,
  CurrentUser,
  ItemTemplate,
  ItemTemplateProperty,
  CollectionTheme,
  ThemeCategory,
  ThemeTemplate,
  WorkspaceMembership,
  WorkspaceUser,
  ItemProperty,
  ItemImage,
} from '../../src/utils/types';
import { Visibility, WorkspaceRole, UserFlag } from '../../src/utils/types';

/**
 * Creates a mock Item with all required properties.
 */
export function createMockItem(overrides: Partial<Item> = {}): Item {
  return {
    id: 1,
    workspaceId: 1,
    collectionId: 1,
    categoryId: null,
    templateKey: null,
    name: 'Test Item',
    summary: 'Test summary',
    description: 'Test description',
    properties: [],
    images: [],
    visibility: Visibility.Default,
    effectiveIsPublic: false,
    userFlag: UserFlag.Have,
    ...overrides,
  };
}

/**
 * Creates a mock Category with all required properties.
 */
export function createMockCategory(overrides: Partial<Category> = {}): Category {
  return {
    workspaceId: 1,
    collectionId: 1,
    categoryId: 1,
    name: 'Test Category',
    description: 'Test description',
    parentCategoryId: null,
    isSystem: false,
    visibility: Visibility.Default,
    effectiveIsPublic: false,
    itemTemplateIds: [],
    ...overrides,
  };
}

/**
 * Creates a mock Collection with all required properties.
 */
export function createMockCollection(overrides: Partial<Collection> = {}): Collection {
  return {
    collectionId: 1,
    workspaceId: 1,
    name: 'Test Collection',
    description: 'Test description',
    heroImageUrl: null,
    slug: 'test-collection',
    visibility: Visibility.Private,
    effectiveIsPublic: false,
    ...overrides,
  };
}

/**
 * Creates a mock WorkspaceMembership with all required properties.
 */
export function createMockWorkspaceMembership(overrides: Partial<WorkspaceMembership> = {}): WorkspaceMembership {
  return {
    workspaceId: 1,
    workspaceName: 'Test Workspace',
    workspaceRole: WorkspaceRole.Normal,
    hasCompletedWelcome: true,
    ...overrides,
  };
}

/**
 * Creates a mock CurrentUser with all required properties.
 */
export function createMockCurrentUser(overrides: Partial<CurrentUser> = {}): CurrentUser {
  const activeWorkspace = createMockWorkspaceMembership(overrides.activeWorkspace);
  return {
    userId: 1,
    email: 'test@example.com',
    activeWorkspace,
    workspaces: [activeWorkspace],
    // Legacy fields
    workspaceId: activeWorkspace.workspaceId,
    workspaceName: activeWorkspace.workspaceName,
    hasCompletedWelcome: activeWorkspace.hasCompletedWelcome,
    hasAcceptedTerms: true,
    isSystemAdministrator: false,
    workspaceRole: activeWorkspace.workspaceRole,
    isWorkspaceAdmin: activeWorkspace.workspaceRole === WorkspaceRole.WorkspaceAdmin,
    ...overrides,
  };
}

/**
 * Creates a mock ItemTemplateProperty.
 */
export function createMockTemplateProperty(overrides: Partial<ItemTemplateProperty> = {}): ItemTemplateProperty {
  return {
    category: 'General',
    name: 'Property',
    ...overrides,
  };
}

/**
 * Creates a mock ItemTemplate with all required properties.
 */
export function createMockItemTemplate(overrides: Partial<ItemTemplate> = {}): ItemTemplate {
  return {
    itemTemplateId: 1,
    templateKey: 'a1b2c3d4-0000-4000-8000-000000000000',
    name: 'Test Template',
    description: 'Test template description',
    isSystem: false,
    properties: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
}

/**
 * Creates a mock ThemeCategory.
 */
export function createMockThemeCategory(overrides: Partial<ThemeCategory> = {}): ThemeCategory {
  return {
    name: 'Test Category',
    description: 'Test category description',
    parentName: null,
    sortOrder: 0,
    ...overrides,
  };
}

/**
 * Creates a mock ThemeTemplate.
 */
export function createMockThemeTemplate(overrides: Partial<ThemeTemplate> = {}): ThemeTemplate {
  return {
    itemTemplateId: 1,
    name: 'Test Template',
    description: 'Test template description',
    properties: [],
    ...overrides,
  };
}

/**
 * Creates a mock CollectionTheme with all required properties.
 */
export function createMockCollectionTheme(overrides: Partial<CollectionTheme> = {}): CollectionTheme {
  return {
    themeId: 1,
    name: 'Test Theme',
    description: 'Test theme description',
    iconName: 'folder',
    sortOrder: 0,
    templates: [],
    categories: [],
    ...overrides,
  };
}

/**
 * Creates a mock WorkspaceUser with all required properties.
 */
export function createMockWorkspaceUser(overrides: Partial<WorkspaceUser> = {}): WorkspaceUser {
  return {
    userId: 1,
    email: 'test@example.com',
    workspaceRole: WorkspaceRole.Normal,
    isLinked: true,
    identityProvider: 'Google',
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

/**
 * Creates a mock ItemProperty.
 */
export function createMockItemProperty(overrides: Partial<ItemProperty> = {}): ItemProperty {
  return {
    category: 'General',
    name: 'Property',
    value: 'Value',
    ...overrides,
  };
}

/**
 * Creates a mock ItemImage.
 */
export function createMockItemImage(overrides: Partial<ItemImage> = {}): ItemImage {
  return {
    url: 'https://example.com/image.jpg',
    alt: 'Test image',
    ...overrides,
  };
}

/**
 * Mock DataContext value for testing components that use useData().
 * Import vi from vitest and pass it to get properly typed mocks.
 */
export function createMockDataContextValue(vi: { fn: () => ReturnType<typeof import('vitest').vi.fn> }, overrides: Record<string, unknown> = {}): import('../../src/contexts/DataContext').DataContextValue {
  return {
    currentCollection: null,
    setCurrentCollection: vi.fn(),
    collections: [],
    collectionsLoading: false,
    collectionsError: null,
    loadCollections: vi.fn(),
    addCollection: vi.fn(),
    setupCollection: vi.fn(),
    updateCollection: vi.fn(),
    deleteCollection: vi.fn(),
    themes: [],
    themesLoading: false,
    themesError: null,
    loadThemes: vi.fn(),
    categories: [],
    categoriesLoading: false,
    categoriesError: null,
    loadCategoriesForCollection: vi.fn(),
    addCategory: vi.fn(),
    updateCategory: vi.fn(),
    deleteCategory: vi.fn(),
    getCategoryTemplates: vi.fn(),
    items: [],
    itemsLoading: false,
    itemsError: null,
    loadItemsForCategory: vi.fn(),
    loadItemById: vi.fn(),
    addItem: vi.fn(),
    updateItem: vi.fn(),
    deleteItem: vi.fn(),
    uploadImage: vi.fn(),
    propertyCategorySuggestions: [],
    propertyNameSuggestions: [],
    loadPropertySuggestions: vi.fn(),
    syncPropertySuggestions: vi.fn(),
    addLocalCategorySuggestion: vi.fn(),
    addLocalNameSuggestion: vi.fn(),
    itemTemplates: [],
    itemTemplatesLoading: false,
    itemTemplatesError: null,
    loadItemTemplates: vi.fn(),
    loadCollectionTemplates: vi.fn(),
    createItemTemplate: vi.fn(),
    updateItemTemplate: vi.fn(),
    deleteItemTemplate: vi.fn(),
    associateTemplateWithCollection: vi.fn(),
    disassociateTemplateFromCollection: vi.fn(),
    ...overrides,
  } as import('../../src/contexts/DataContext').DataContextValue;
}
