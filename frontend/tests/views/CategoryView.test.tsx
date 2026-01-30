import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import CategoryView from '../../src/views/CategoryView';
import { useData } from '../../src/contexts/DataContext';
import type { Collection, Category, Item } from '../../src/utils/types';

vi.mock('../../src/contexts/DataContext', () => ({
  useData: vi.fn(),
}));

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

function renderWithRouter(initialRoute: string) {
  return render(
    <MemoryRouter initialEntries={[initialRoute]}>
      <Routes>
        <Route path="/collections/:collectionId" element={<CategoryView />} />
        <Route path="/collections/:collectionId/categories/:categoryId" element={<CategoryView />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('CategoryView', () => {
  const mockCollections: Collection[] = [
    { collectionId: 1, tenantId: 1, name: 'Test Collection', description: 'Test desc', heroImageUrl: null, slug: 'test', isPublic: true },
  ];

  const mockCategories: Category[] = [
    { tenantId: 1, categoryId: 1, collectionId: 1, name: 'Root Category', description: 'Root desc', parentCategoryId: null, isSystem: false, isPublicOverride: null, effectiveIsPublic: true, itemTemplateIds: [] },
    { tenantId: 1, categoryId: 2, collectionId: 1, name: 'Child Category', description: 'Child desc', parentCategoryId: 1, isSystem: false, isPublicOverride: null, effectiveIsPublic: true, itemTemplateIds: [] },
  ];

  const mockItems: Item[] = [
    {
      id: 1,
      tenantId: 1,
      collectionId: 1,
      categoryId: 1,
      name: 'Test Item 1',
      summary: 'Summary 1',
      description: 'Description 1',
      properties: [],
      images: [],
      isPublicOverride: null,
      effectiveIsPublic: true,
    },
    {
      id: 2,
      tenantId: 1,
      collectionId: 1,
      categoryId: 1,
      name: 'Test Item 2',
      summary: 'Summary 2',
      description: 'Description 2',
      properties: [],
      images: [],
      isPublicOverride: null,
      effectiveIsPublic: true,
    },
  ];

  const mockDataContext = {
    collections: mockCollections,
    collectionsLoading: false,
    loadCollections: vi.fn(),
    currentCollection: mockCollections[0],
    setCurrentCollection: vi.fn(),
    categories: mockCategories,
    loadCategoriesForCollection: vi.fn(),
    items: mockItems,
    loadItemsForCategory: vi.fn(),
    loadPropertySuggestions: vi.fn(),
    itemTemplates: [],
    itemTemplatesLoading: false,
    itemTemplatesError: null,
    loadItemTemplates: vi.fn(async () => []),
    loadCollectionTemplates: vi.fn(async () => []),
    getCategoryTemplates: vi.fn(async () => []),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    (useData as ReturnType<typeof vi.fn>).mockReturnValue(mockDataContext);
  });

  describe('deep linking', () => {
    it('should load collection data when navigating directly with empty collections', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        collections: [],
        currentCollection: null,
      });

      renderWithRouter('/collections/1');

      expect(mockDataContext.loadCollections).toHaveBeenCalled();
    });

    it('should set current collection when collections are loaded', async () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: null, // Not yet set
      });

      renderWithRouter('/collections/1');

      await waitFor(() => {
        expect(mockDataContext.setCurrentCollection).toHaveBeenCalledWith(mockCollections[0]);
      });
    });

    it('should load categories for collection', async () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: null, // Not yet set
      });

      renderWithRouter('/collections/1');

      await waitFor(() => {
        expect(mockDataContext.loadCategoriesForCollection).toHaveBeenCalledWith(1);
      });
    });

    it('should redirect to collections if collection not found', async () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: null,
        collections: [{ collectionId: 99, tenantId: 1, name: 'Other', description: '', heroImageUrl: null, slug: 'other' }],
      });

      renderWithRouter('/collections/999');

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/collections', { replace: true });
      });
    });
  });

  describe('category view without selection', () => {
    it('should show placeholder when no category selected', () => {
      renderWithRouter('/collections/1');

      expect(screen.getByText('Select a category to browse items')).toBeInTheDocument();
    });

    it('should show category tree', () => {
      renderWithRouter('/collections/1');

      expect(screen.getAllByText('Root Category').length).toBeGreaterThanOrEqual(1);
    });

    it('should navigate when category is clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1');

      // Click on the category tree item
      const categoryButton = screen.getAllByText('Root Category').find(el => el.classList.contains('categoryTree__item'));
      expect(categoryButton).toBeTruthy();
      await user.click(categoryButton!);

      expect(mockNavigate).toHaveBeenCalledWith('/collections/1/categories/1');
    });
  });

  describe('category view with selection', () => {
    it('should load items when category is selected', () => {
      renderWithRouter('/collections/1/categories/1');

      expect(mockDataContext.loadItemsForCategory).toHaveBeenCalledWith(1);
    });

    it('should show item list', () => {
      renderWithRouter('/collections/1/categories/1');

      expect(screen.getByText('Test Item 1')).toBeInTheDocument();
      expect(screen.getByText('Test Item 2')).toBeInTheDocument();
    });

    it('should show back to categories button', () => {
      renderWithRouter('/collections/1/categories/1');

      expect(screen.getByText('← Categories')).toBeInTheDocument();
    });

    it('should navigate back to collection when back is clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1/categories/1');

      await user.click(screen.getByText('← Categories'));

      expect(mockNavigate).toHaveBeenCalledWith('/collections/1');
    });

    it('should navigate to item when item is clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1/categories/1');

      await user.click(screen.getByText('Test Item 1'));

      expect(mockNavigate).toHaveBeenCalledWith('/collections/1/items/1');
    });

    it('should navigate to add item when add button is clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1/categories/1');

      await user.click(screen.getByText('+ Add Item'));

      expect(mockNavigate).toHaveBeenCalledWith('/collections/1/items/new?categoryId=1');
    });
  });

  describe('subcategory dropdown', () => {
    it('should show subcategory dropdown when category has children', () => {
      renderWithRouter('/collections/1/categories/1');

      expect(screen.getByText('Filter by subcategory:')).toBeInTheDocument();
    });

    it('should not show subcategory dropdown for leaf categories', () => {
      renderWithRouter('/collections/1/categories/2');

      expect(screen.queryByText('Filter by subcategory:')).not.toBeInTheDocument();
    });
  });

  describe('loading states', () => {
    it('should show loading state when collections are loading', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        collectionsLoading: true,
      });

      renderWithRouter('/collections/1');

      expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('should show collection not found when no current collection', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: null,
      });

      renderWithRouter('/collections/1');

      expect(screen.getByText('Collection not found')).toBeInTheDocument();
    });
  });
});
