import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import App from '../src/App';
import CollectionView from '../src/views/CollectionView';
import CategoryView from '../src/views/CategoryView';
import ItemView from '../src/views/ItemView';
import { useData } from '../src/contexts/useData';
import { useUser } from '../src/contexts/useUser';
import { useToast } from '../src/contexts/useToast';
import type { Category, Item, Collection } from '../src/utils/types';
import { Visibility, UserFlag, WorkspaceRole } from '../src/utils/types';

// Mock the DataContext
vi.mock('../src/contexts/useData', () => ({
  useData: vi.fn(),
  DataProvider: ({ children }: { children: React.ReactNode }) => children,
}));

// Mock the UserContext
vi.mock('../src/contexts/useUser', () => ({
  useUser: vi.fn(),
}));

// Mock the ToastContext
vi.mock('../src/contexts/useToast', () => ({
  useToast: vi.fn(() => ({
    toasts: [],
    showToast: vi.fn(),
    dismissToast: vi.fn(),
  })),
}));

// Helper to render with router
function renderWithRouter(initialRoute = '/collections') {
  return render(
    <MemoryRouter initialEntries={[initialRoute]}>
      <Routes>
        <Route path="/" element={<App />}>
          <Route path="collections" element={<CollectionView />} />
          <Route path="collections/:collectionId" element={<CategoryView />} />
          <Route path="collections/:collectionId/categories/:categoryId" element={<CategoryView />} />
          <Route path="collections/:collectionId/items/:itemId" element={<ItemView />} />
        </Route>
      </Routes>
    </MemoryRouter>
  );
}

describe('App with Router', () => {
  const mockCollections: Collection[] = [
    { collectionId: 1, workspaceId: 1, name: 'Test Collection', description: 'Test desc', heroImageUrl: null, slug: 'test', visibility: Visibility.Public, effectiveIsPublic: true },
  ];

  const mockCategories: Category[] = [
    { workspaceId: 1, categoryId: 1, collectionId: 1, name: 'Root Category', description: 'Root desc', parentCategoryId: null, isSystem: false, visibility: Visibility.Private, effectiveIsPublic: true, itemTemplateIds: [], sortOrder: 0 },
    { workspaceId: 1, categoryId: 2, collectionId: 1, name: 'Child Category', description: 'Child desc', parentCategoryId: 1, isSystem: false, visibility: Visibility.Private, effectiveIsPublic: true, itemTemplateIds: [], sortOrder: 0 },
  ];

  const mockItems: Item[] = [
    {
      id: 1,
      workspaceId: 1,
      collectionId: 1,
      categoryId: 1,
      templateKey: null,
      name: 'Test Item 1',
      summary: 'Summary 1',
      description: 'Description 1',
      properties: [{ category: 'General', name: 'Prop', value: 'Value' }],
      images: [{ url: 'https://example.com/img.jpg', alt: 'Image' }],
      visibility: Visibility.Private,
      effectiveIsPublic: true,
      userFlag: UserFlag.Have,
    },
    {
      id: 2,
      workspaceId: 1,
      collectionId: 1,
      categoryId: 1,
      templateKey: null,
      name: 'Test Item 2',
      summary: 'Summary 2',
      description: 'Description 2',
      properties: [],
      images: [],
      visibility: Visibility.Private,
      effectiveIsPublic: true,
      userFlag: UserFlag.Have,
    },
  ];

  const mockDataContext = {
    collections: mockCollections,
    collectionsLoading: false,
    collectionsError: null,
    loadCollections: vi.fn(),
    currentCollection: null,
    setCurrentCollection: vi.fn(),
    categories: mockCategories,
    categoriesLoading: false,
    categoriesError: null,
    loadCategoriesForCollection: vi.fn(),
    items: mockItems,
    itemsLoading: false,
    itemsError: null,
    loadItemsForCategory: vi.fn(),
    loadItemById: vi.fn(async () => null),
    addItem: vi.fn(async () => 3),
    updateItem: vi.fn(async () => {}),
    deleteItem: vi.fn(async () => {}),
    addCategory: vi.fn(async () => 4),
    updateCategory: vi.fn(async () => {}),
    deleteCategory: vi.fn(async () => {}),
    addCollection: vi.fn(),
    updateCollection: vi.fn(),
    deleteCollection: vi.fn(),
    loadPropertySuggestions: vi.fn(),
    syncPropertySuggestions: vi.fn(),
    propertyCategorySuggestions: [],
    propertyNameSuggestions: [],
    addLocalCategorySuggestion: vi.fn(),
    addLocalNameSuggestion: vi.fn(),
    itemTemplates: [],
    itemTemplatesLoading: false,
    itemTemplatesError: null,
    loadItemTemplates: vi.fn(async () => []),
    loadCollectionTemplates: vi.fn(async () => []),
    getCategoryTemplates: vi.fn(async () => []),
  };

  const mockUserWithSlug = {
    user: {
      userId: 1,
      email: 'test@example.com',
      activeWorkspace: {
        workspaceId: 1,
        workspaceName: 'Test Workspace',
        workspaceRole: WorkspaceRole.WorkspaceAdmin,
        hasCompletedWelcome: true,
        slug: 'my-gallery',
      },
      workspaces: [{
        workspaceId: 1,
        workspaceName: 'Test Workspace',
        workspaceRole: WorkspaceRole.WorkspaceAdmin,
        hasCompletedWelcome: true,
        slug: 'my-gallery',
      }],
      workspaceId: 1,
      workspaceName: 'Test Workspace',
      hasCompletedWelcome: true,
      hasAcceptedTerms: true,
      isSystemAdministrator: false,
      workspaceRole: WorkspaceRole.WorkspaceAdmin,
      isWorkspaceAdmin: true,
    },
    loading: false,
    error: null,
    refetch: vi.fn(),
    logout: vi.fn(),
  };

  const mockUserWithoutSlug = {
    ...mockUserWithSlug,
    user: {
      ...mockUserWithSlug.user,
      activeWorkspace: {
        ...mockUserWithSlug.user.activeWorkspace,
        slug: null,
      },
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    (useData as ReturnType<typeof vi.fn>).mockReturnValue(mockDataContext);
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue(mockUserWithSlug);
    (useToast as ReturnType<typeof vi.fn>).mockReturnValue({
      toasts: [],
      showToast: vi.fn(),
      dismissToast: vi.fn(),
    });
  });

  describe('routing', () => {
    it('should render collections page at /collections', () => {
      renderWithRouter('/collections');

      expect(screen.getByRole('heading', { level: 1, name: 'Collections' })).toBeInTheDocument();
    });

    it('should show loading state while collections are loading', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        collectionsLoading: true,
        collections: [],
      });

      renderWithRouter('/collections');

      expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('should auto-navigate to single collection', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: mockCollections[0],
      });

      renderWithRouter('/collections/1');

      expect(screen.getByText('Test Collection')).toBeInTheDocument();
    });
  });

  describe('deep linking', () => {
    it('should load collection data when navigating directly to collection', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: mockCollections[0],
      });

      renderWithRouter('/collections/1');

      expect(mockDataContext.loadCollections).toHaveBeenCalled();
    });

    it('should load category items when navigating directly to category', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: mockCollections[0],
      });

      renderWithRouter('/collections/1/categories/1');

      expect(screen.getByText('Test Collection')).toBeInTheDocument();
    });

    it('should load item when navigating directly to item', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: mockCollections[0],
      });

      renderWithRouter('/collections/1/items/1');

      expect(screen.getByText('Test Collection')).toBeInTheDocument();
    });
  });

  describe('header', () => {
    it('should display collection name in header when viewing collection', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: mockCollections[0],
      });

      renderWithRouter('/collections/1');

      expect(screen.getByRole('heading', { level: 1, name: 'Test Collection' })).toBeInTheDocument();
    });

    it('should show back button when multiple collections exist', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        collections: [
          ...mockCollections,
          { collectionId: 2, workspaceId: 1, name: 'Second Collection', description: '', heroImageUrl: null, slug: 'second' },
        ],
        currentCollection: mockCollections[0],
      });

      renderWithRouter('/collections/1');

      expect(screen.getByText('\u2190 All Collections')).toBeInTheDocument();
    });

    it('should show Public Gallery link when workspace has slug', () => {
      renderWithRouter('/collections');

      const link = screen.getByText('Public Gallery');
      expect(link).toBeInTheDocument();
      expect(link).toHaveAttribute('href', '/public/my-gallery');
      expect(link).toHaveAttribute('target', '_blank');
    });

    it('should show Set Up Public Gallery button when workspace has no slug', () => {
      (useUser as ReturnType<typeof vi.fn>).mockReturnValue(mockUserWithoutSlug);

      renderWithRouter('/collections');

      expect(screen.getByText('Set Up Public Gallery')).toBeInTheDocument();
      expect(screen.queryByText('Public Gallery')).not.toBeInTheDocument();
    });
  });
});
