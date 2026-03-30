import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import CategoryView from '../../src/views/CategoryView';
import { useData } from '../../src/contexts/useData';
import type { Collection, Category, Item } from '../../src/utils/types';
import { Visibility, UserFlag } from '../../src/utils/types';

vi.mock('../../src/contexts/useData', () => ({
  useData: vi.fn(),
}));

const mockRequestPublish = vi.fn();
const mockRequestUnpublish = vi.fn();

vi.mock('../../src/contexts/usePublish', () => ({
  usePublish: () => ({
    requestPublish: mockRequestPublish,
    requestUnpublish: mockRequestUnpublish,
    pendingIntent: null,
    clearIntent: vi.fn(),
  }),
}));

vi.mock('../../src/api/collections', () => ({
  collectionsApi: {
    getStatistics: vi.fn().mockResolvedValue({
      itemCount: 0,
      imageCount: 0,
      totalImageSizeBytes: 0,
      topViewedItems: [],
      recentlyAddedItems: [],
    }),
  },
}));

vi.mock('../../src/components/category', () => ({
  CategoryManagerModal: ({ collectionId, isOpen, onClose }: { collectionId: number; isOpen: boolean; onClose: () => void }) => (
    isOpen ? <div data-testid="category-manager-modal" data-collection-id={collectionId}><button onClick={onClose}>Close Manager</button></div> : null
  ),
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
      properties: [],
      images: [],
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
    loadCollections: vi.fn(),
    currentCollection: mockCollections[0],
    setCurrentCollection: vi.fn(),
    categories: mockCategories,
    categoriesLoading: false,
    categoriesError: null,
    loadCategoriesForCollection: vi.fn(),
    items: mockItems,
    itemsLoading: false,
    itemsError: null,
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
        collections: [{ collectionId: 99, workspaceId: 1, name: 'Other', description: '', heroImageUrl: null, slug: 'other' }],
      });

      renderWithRouter('/collections/999');

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/collections', { replace: true });
      });
    });
  });

  describe('category view without selection', () => {
    it('should show collection dashboard when no category selected', async () => {
      renderWithRouter('/collections/1');

      await waitFor(() => {
        expect(screen.getByText('No items yet. Select a category and start adding items.')).toBeInTheDocument();
      });
    });

    it('should show category tree', () => {
      renderWithRouter('/collections/1');

      expect(screen.getAllByText('Root Category').length).toBeGreaterThanOrEqual(1);
    });

    it('should navigate when category is clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1');

      // Click on the category nav row
      const categoryButton = screen.getAllByText('Root Category').find(el => el.classList.contains('categoryNav__name'));
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

      expect(screen.getByText('\u2190 Categories')).toBeInTheDocument();
    });

    it('should navigate back to collection when back is clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1/categories/1');

      await user.click(screen.getByText('\u2190 Categories'));

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

    it('should render collection name as a link to the dashboard', () => {
      renderWithRouter('/collections/1/categories/1');

      const titleLink = screen.getByRole('link', { name: 'Test Collection' });
      expect(titleLink).toHaveAttribute('href', '/collections/1');
      expect(titleLink).toHaveClass('collection-title-bar__title-link');
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

  describe('sidebar collapse', () => {
    it('should render collapse button inside CategoryNav', () => {
      renderWithRouter('/collections/1');

      expect(screen.getByLabelText('Collapse categories')).toBeInTheDocument();
    });

    it('should hide CategoryNav when sidebar is collapsed', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1');

      await user.click(screen.getByLabelText('Collapse categories'));
      expect(screen.queryByText('Root Category')).not.toBeInTheDocument();
      expect(screen.getByLabelText('Expand sidebar')).toBeInTheDocument();
    });

    it('should show CategoryNav when sidebar is expanded again', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1');

      await user.click(screen.getByLabelText('Collapse categories'));
      await user.click(screen.getByLabelText('Expand sidebar'));
      expect(screen.getAllByText('Root Category').length).toBeGreaterThanOrEqual(1);
    });

    it('should render collapse button when category is selected', () => {
      renderWithRouter('/collections/1/categories/1');

      expect(screen.getByLabelText('Collapse categories')).toBeInTheDocument();
    });

    it('should add collapsed class when sidebar is collapsed', async () => {
      const user = userEvent.setup();
      const { container } = renderWithRouter('/collections/1');

      await user.click(screen.getByLabelText('Collapse categories'));
      expect(container.querySelector('.app__layout--sidebar-collapsed')).toBeInTheDocument();
    });

    it('should start collapsed on small viewports', () => {
      const originalMatchMedia = window.matchMedia;
      window.matchMedia = vi.fn().mockImplementation((query: string) => ({
        matches: query === '(max-width: 1024px)',
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      }));

      renderWithRouter('/collections/1');

      expect(screen.getByLabelText('Expand sidebar')).toBeInTheDocument();
      expect(screen.queryByText('Root Category')).not.toBeInTheDocument();

      window.matchMedia = originalMatchMedia;
    });
  });

  describe('CategoryManagerModal integration', () => {
    it('should open CategoryManagerModal when Edit button in CategoryNav is clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1');

      // CategoryManagerModal should not be visible initially
      expect(screen.queryByTestId('category-manager-modal')).not.toBeInTheDocument();

      // Click the Edit button in CategoryNav
      await user.click(screen.getByLabelText('Edit categories'));

      // CategoryManagerModal should now be visible
      expect(screen.getByTestId('category-manager-modal')).toBeInTheDocument();
    });

    it('should pass correct collectionId to CategoryManagerModal', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1');

      await user.click(screen.getByLabelText('Edit categories'));

      const modal = screen.getByTestId('category-manager-modal');
      expect(modal).toHaveAttribute('data-collection-id', '1');
    });

    it('should close CategoryManagerModal when onClose is called', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1');

      await user.click(screen.getByLabelText('Edit categories'));
      expect(screen.getByTestId('category-manager-modal')).toBeInTheDocument();

      await user.click(screen.getByText('Close Manager'));
      expect(screen.queryByTestId('category-manager-modal')).not.toBeInTheDocument();
    });

    it('should open CategoryManagerModal from category selected view', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1/categories/1');

      expect(screen.queryByTestId('category-manager-modal')).not.toBeInTheDocument();

      await user.click(screen.getByLabelText('Edit categories'));

      expect(screen.getByTestId('category-manager-modal')).toBeInTheDocument();
      expect(screen.getByTestId('category-manager-modal')).toHaveAttribute('data-collection-id', '1');
    });
  });

  describe('collection publish/unpublish in title bar', () => {
    const privateCollection = { ...mockCollections[0], effectiveIsPublic: false, visibility: Visibility.Private };
    const privateCategories = mockCategories.map(c => ({ ...c, effectiveIsPublic: false }));
    const privateItems = mockItems.map(i => ({ ...i, effectiveIsPublic: false }));

    it('should show PublishButton for private collection (no category selected)', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: privateCollection,
        collections: [privateCollection],
        categories: privateCategories,
        items: privateItems,
      });

      renderWithRouter('/collections/1');
      // The collection title bar should have a Publish button
      expect(screen.getAllByText('Publish').length).toBeGreaterThanOrEqual(1);
    });

    it('should show PublicBadge for public collection (no category selected)', () => {
      renderWithRouter('/collections/1');
      // Default mock has effectiveIsPublic: true for collection
      expect(screen.getAllByText('Public').length).toBeGreaterThanOrEqual(1);
    });

    it('should show PublishButton for private collection (with category selected)', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: privateCollection,
        collections: [privateCollection],
        categories: privateCategories,
        items: privateItems,
      });

      renderWithRouter('/collections/1/categories/1');
      const publishButtons = screen.getAllByText('Publish');
      expect(publishButtons.length).toBeGreaterThanOrEqual(1);
    });

    it('should show PublicBadge for public collection (with category selected)', () => {
      renderWithRouter('/collections/1/categories/1');
      // Default mock has effectiveIsPublic: true
      expect(screen.getAllByText('Public').length).toBeGreaterThanOrEqual(1);
    });

    it('should call requestPublish when clicking Publish on collection title bar', async () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: privateCollection,
        collections: [privateCollection],
        categories: [],
        items: [],
      });

      const user = userEvent.setup();
      renderWithRouter('/collections/1');

      await user.click(screen.getByText('Publish'));

      expect(mockRequestPublish).toHaveBeenCalledWith([{ type: 'collection', id: 1 }]);
    });

    it('should call requestUnpublish when clicking PublicBadge on collection title bar', async () => {
      const user = userEvent.setup();
      const { container } = renderWithRouter('/collections/1');

      // Target the Public badge inside the collection-title-bar specifically
      const titleBar = container.querySelector('.collection-title-bar');
      const badge = titleBar!.querySelector('.collection-title-bar__badge');
      await user.click(badge!);

      expect(mockRequestUnpublish).toHaveBeenCalledWith([{ type: 'collection', id: 1 }]);
    });
  });

  describe('snapshots', () => {
    it('should match snapshot with category selected', () => {
      const { container } = renderWithRouter('/collections/1/categories/1');
      expect(container).toMatchSnapshot();
    });
  });
});
