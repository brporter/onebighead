import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import ItemView from '../../src/views/ItemView';
import { useCollectionsData as useDataHook } from '../../src/contexts/useData';
import type { Collection, Category, Item } from '../../src/utils/types';
import { Visibility, UserFlag } from '../../src/utils/types';
import { bulkUpdatesApi } from '../../src/api/bulkUpdates';
import { deferred } from '../testUtils/deferred';

const useData = useDataHook as () => import('../testUtils/dataTypes').DataContextValue;

vi.mock('../../src/contexts/useData', async () => {
  const { mockDataHooks } = await import('../testUtils/mockDataHooks');
  return mockDataHooks({
  useData: vi.fn(),
});
});
vi.mock('../../src/api/bulkUpdates', () => ({ bulkUpdatesApi: { preview: vi.fn() } }));

const mockRecordView = vi.fn().mockResolvedValue(undefined);
vi.mock('../../src/api/items', () => ({
  itemsApi: {
    recordView: (...args: unknown[]) => mockRecordView(...args),
  },
}));

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

async function renderWithRouter(initialRoute: string) {
  const router = createMemoryRouter([
    { path: '/collections/:collectionId/items/:itemId', element: <ItemView /> },
  ], { initialEntries: [initialRoute] });
  let view!: ReturnType<typeof render>;
  await act(async () => { view = render(<RouterProvider router={router} />); });
  return view;
}

describe('ItemView', () => {
  const mockCollections: Collection[] = [
    { collectionId: 1, workspaceId: 1, name: 'Test Collection', description: 'Test desc', heroImageUrl: null, slug: 'test', visibility: Visibility.Public, effectiveIsPublic: true },
  ];

  const mockCategories: Category[] = [
    { workspaceId: 1, categoryId: 1, collectionId: 1, name: 'Root Category', description: 'Root desc', parentCategoryId: null, isSystem: false, visibility: Visibility.Private, effectiveIsPublic: true, itemTemplateIds: [], sortOrder: 0 },
  ];

  const mockItems: Item[] = [
    {
      id: 1,
      workspaceId: 1,
      collectionId: 1,
      categoryId: 1,
      templateKey: null,
      name: 'Test Item',
      summary: 'Test summary',
      description: 'Test description',
      properties: [{ category: 'General', name: 'Color', value: 'Blue' }],
      images: [{ url: 'https://example.com/img.jpg', alt: 'Test image' }],
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
    currentCollection: mockCollections[0],
    setCurrentCollection: vi.fn(),
    categories: mockCategories,
    categoriesLoading: false,
    categoriesError: null,
    loadCategoriesForCollection: vi.fn(),
    items: mockItems,
    itemDetails: new Map<number, Item | null>(mockItems.map(item => [item.id!, item])),
    itemsLoading: false,
    itemsError: null,
    loadItemsForCategory: vi.fn(),
    loadItemById: vi.fn(async () => null),
    addItem: vi.fn(async () => 2),
    updateItem: vi.fn(async (_id: number, item: Partial<Item>) => ({ ...mockItems[0], ...item })),
    deleteItem: vi.fn(async () => {}),
    invalidateItemCache: vi.fn(),
    loadPropertySuggestions: vi.fn(),
    syncPropertySuggestions: vi.fn(),
    propertyCategorySuggestions: [],
    propertyNameSuggestions: [],
    addLocalCategorySuggestion: vi.fn(),
    addLocalNameSuggestion: vi.fn(),
    // Item templates
    fetchItemTemplates: vi.fn(async () => []),
    loadCollectionTemplates: vi.fn(async () => []),
    createItemTemplate: vi.fn(async () => ({ itemTemplateId: 1, templateKey: 'a1b2c3d4-0000-4000-8000-000000000000', name: 'Test', description: '', isShared: false, isOwner: true, properties: [], createdAt: '', updatedAt: '' })),
    updateItemTemplate: vi.fn(async () => ({ itemTemplateId: 1, templateKey: 'a1b2c3d4-0000-4000-8000-000000000000', name: 'Test', description: '', isShared: false, isOwner: true, properties: [], createdAt: '', updatedAt: '' })),
    deleteItemTemplate: vi.fn(async () => {}),
    associateTemplateWithCollection: vi.fn(async () => {}),
    disassociateTemplateFromCollection: vi.fn(async () => {}),
    getCategoryTemplates: vi.fn(async () => []),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockDataContext.itemDetails = new Map(mockItems.map(item => [item.id!, item]));
    vi.mocked(bulkUpdatesApi.preview).mockResolvedValue({ affectedItemCount: 1 });
    (useData as ReturnType<typeof vi.fn>).mockReturnValue(mockDataContext);
  });

  describe('viewing existing item', () => {
    it('should display item details', async () => {
      await renderWithRouter('/collections/1/items/1');

      expect(screen.getByText('Test Item')).toBeInTheDocument();
      expect(screen.getByText('Test description')).toBeInTheDocument();
    });

    it('should show edit button', async () => {
      await renderWithRouter('/collections/1/items/1');

      expect(screen.getByText('Edit')).toBeInTheDocument();
    });

    it('should show back button', async () => {
      await renderWithRouter('/collections/1/items/1');

      expect(screen.getByText('← Back to items')).toBeInTheDocument();
    });

    it('should navigate back to category when back is clicked', async () => {
      const user = userEvent.setup();
      await renderWithRouter('/collections/1/items/1');

      await user.click(screen.getByText('← Back to items'));

      expect(mockNavigate).toHaveBeenCalledWith('/collections/1/categories/1');
    });

    it('should show item not found when item does not exist', async () => {
      // Provide items array with other items but not the requested one, and loadItemById returns null
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        items: [{ ...mockItems[0], id: 100 }], // Different ID
        loadItemById: vi.fn(async () => null), // Item not found
      });

      await renderWithRouter('/collections/1/items/999');

      await waitFor(() => {
        expect(screen.getByText('Item not found')).toBeInTheDocument();
      });
    });
  });

  describe('editing item', () => {
    it('should show editor when edit is clicked', async () => {
      const user = userEvent.setup();
      await renderWithRouter('/collections/1/items/1');

      await user.click(screen.getByText('Edit'));

      expect(screen.getByLabelText('Name')).toBeInTheDocument();
    });

    it('should call updateItem when saving', async () => {
      const user = userEvent.setup();
      await renderWithRouter('/collections/1/items/1');

      await user.click(screen.getByText('Edit'));
      
      const nameInput = screen.getByLabelText('Name');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Item');
      await user.click(screen.getByText('Save Changes'));

      expect(mockDataContext.updateItem).toHaveBeenCalledWith(1, expect.objectContaining({
        name: 'Updated Item',
      }));
    });

    it('should return to detail view when cancelling edit', async () => {
      const user = userEvent.setup();
      await renderWithRouter('/collections/1/items/1');

      // Enter edit mode
      await user.click(screen.getByRole('button', { name: 'Edit' }));
      
      // Verify we're in edit mode
      expect(screen.getByLabelText('Name')).toBeInTheDocument();
      
      // Click Cancel to exit edit mode
      const cancelButton = screen.getByRole('button', { name: 'Cancel' });
      await user.click(cancelButton);

      // Should be back in view mode with Edit button visible
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument();
      });
    });
  });

  describe('deleting item', () => {
    it('should call deleteItem and navigate back', async () => {
      const user = userEvent.setup();
      vi.spyOn(window, 'confirm').mockReturnValue(true);
      
      await renderWithRouter('/collections/1/items/1');

      await user.click(screen.getByText('Edit'));
      await user.click(screen.getByText('Delete'));

      expect(mockDataContext.deleteItem).toHaveBeenCalledWith(1);
      expect(mockNavigate).toHaveBeenCalledWith('/collections/1/categories/1');
    });
  });

  describe('creating new item', () => {
    it('should show template selector first for new item', async () => {
      await renderWithRouter('/collections/1/items/new?categoryId=1');

      await waitFor(() => {
        expect(screen.getByText('Choose a Template')).toBeInTheDocument();
      });
    });

    it('should show editor after selecting start from scratch', async () => {
      const user = userEvent.setup();
      await renderWithRouter('/collections/1/items/new?categoryId=1');

      await waitFor(() => {
        expect(screen.getByText('Start from scratch')).toBeInTheDocument();
      });
      
      await user.click(screen.getByText('Start from scratch'));

      await waitFor(() => {
        expect(screen.getByText('Add New Item')).toBeInTheDocument();
      });
    });

    it('should call addItem when creating', async () => {
      const user = userEvent.setup();
      await renderWithRouter('/collections/1/items/new?categoryId=1');

      // First dismiss template selector
      await waitFor(() => {
        expect(screen.getByText('Start from scratch')).toBeInTheDocument();
      });
      await user.click(screen.getByText('Start from scratch'));

      await waitFor(() => {
        expect(screen.getByLabelText('Name')).toBeInTheDocument();
      });
      
      await user.type(screen.getByLabelText('Name'), 'New Item');
      await user.click(screen.getByText('Create Item'));

      expect(mockDataContext.addItem).toHaveBeenCalled();
    });

    it('should navigate back after creating', async () => {
      const user = userEvent.setup();
      await renderWithRouter('/collections/1/items/new?categoryId=1');

      // First dismiss template selector
      await waitFor(() => {
        expect(screen.getByText('Start from scratch')).toBeInTheDocument();
      });
      await user.click(screen.getByText('Start from scratch'));

      await waitFor(() => {
        expect(screen.getByLabelText('Name')).toBeInTheDocument();
      });
      
      await user.type(screen.getByLabelText('Name'), 'New Item');
      await user.click(screen.getByText('Create Item'));

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/collections/1/categories/1');
      });
    });

    it('should navigate back when cancelling new item', async () => {
      const user = userEvent.setup();
      await renderWithRouter('/collections/1/items/new?categoryId=1');

      // First dismiss template selector
      await waitFor(() => {
        expect(screen.getByText('Start from scratch')).toBeInTheDocument();
      });
      await user.click(screen.getByText('Start from scratch'));

      await waitFor(() => {
        expect(screen.getByLabelText('Name')).toBeInTheDocument();
      });

      // Find the Cancel button in the editor form
      const cancelButton = screen.getByRole('button', { name: 'Cancel' });
      await user.click(cancelButton);

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/collections/1/categories/1');
      });
    });
  });

  describe('deep linking', () => {
    it('should load collection data when navigating directly to item with empty collections', async () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        collections: [],
        currentCollection: null,
      });

      await renderWithRouter('/collections/1/items/1');

      expect(mockDataContext.loadCollections).toHaveBeenCalled();
    });

    it('should offer recovery if the collection is not found', async () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: null,
        collections: [{ collectionId: 99, workspaceId: 1, name: 'Other', description: '', heroImageUrl: null, slug: 'other' }],
      });

      await renderWithRouter('/collections/999/items/1');

      await waitFor(() => {
        expect(screen.getByText('Collection not found')).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'All Collections' })).toHaveAttribute('href', '/collections');
      });
    });
  });

  describe('loading states', () => {
    it('should show loading state when collections are loading', async () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        collectionsLoading: true,
      });

      await renderWithRouter('/collections/1/items/1');

      expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('should show collection not found when no current collection', async () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: null,
        collections: [{ ...mockCollections[0], collectionId: 999 }], // Different collection ID
      });

      await renderWithRouter('/collections/1/items/1');

      await waitFor(() => {
        expect(screen.getByText('Collection not found')).toBeInTheDocument();
      });
    });
  });

  describe('view tracking', () => {
    it('should record a view exactly once for the item', async () => {
      await renderWithRouter('/collections/1/items/1');

      await waitFor(() => {
        expect(mockRecordView).toHaveBeenCalledWith(1);
      });
      expect(mockRecordView).toHaveBeenCalledTimes(1);
    });
  });

  describe('collection title link', () => {
    it('should render collection name as a link to the dashboard', async () => {
      await renderWithRouter('/collections/1/items/1');

      const titleLink = screen.getByRole('link', { name: 'Test Collection' });
      expect(titleLink).toHaveAttribute('href', '/collections/1');
      expect(titleLink.closest('h1')).toBeInTheDocument();
    });
  });

  describe('route and request recovery', () => {
    it.each(['/collections/1abc/items/1', '/collections/1/items/2abc', '/collections/1/items/new?categoryId=bad'])('rejects malformed links: %s', async route => {
      await renderWithRouter(route);
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid item link');
      expect(mockDataContext.loadItemById).not.toHaveBeenCalled();
    });

    it('retries collection failures explicitly', async () => {
      vi.mocked(useData).mockReturnValue({ ...mockDataContext, collectionsError: 'Offline' } as unknown as ReturnType<typeof useData>);
      await renderWithRouter('/collections/1/items/1');
      expect(screen.getByRole('alert')).toHaveTextContent('Offline');
      await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
      expect(mockDataContext.loadCollections).toHaveBeenCalledOnce();
    });

    it('retries category failures explicitly', async () => {
      vi.mocked(useData).mockReturnValue({ ...mockDataContext, categoriesError: 'Offline' } as unknown as ReturnType<typeof useData>);
      await renderWithRouter('/collections/1/items/1');
      await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
      expect(mockDataContext.loadCategoriesForCollection).toHaveBeenCalledExactlyOnceWith(1);
    });

    it('shows loading, a recoverable fetch error, and the successful retry', async () => {
      const pending = deferred<Item | null>();
      const recovered = { ...mockItems[0], id: 2, name: 'Recovered item' };
      const load = vi.fn().mockReturnValueOnce(pending.promise).mockImplementation(async () => {
        mockDataContext.itemDetails.set(2, recovered);
        return recovered;
      });
      vi.mocked(useData).mockReturnValue({ ...mockDataContext, items: [], loadItemById: load } as unknown as ReturnType<typeof useData>);
      await renderWithRouter('/collections/1/items/2');
      expect(screen.getByRole('status')).toHaveTextContent('Loading item');
      pending.reject(new Error('Item request failed'));
      expect(await screen.findByRole('alert')).toHaveTextContent('Item request failed');
      await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
      expect(await screen.findByText('Recovered item')).toBeInTheDocument();
      expect(load).toHaveBeenCalledTimes(2);
      expect(mockDataContext.loadItemsForCategory).not.toHaveBeenCalled();
    });

    it('does not display items belonging to another collection', async () => {
      vi.mocked(useData).mockReturnValue({ ...mockDataContext, items: [],
        itemDetails: new Map([[1, { ...mockItems[0], collectionId: 2 }]]),
        loadItemById: vi.fn().mockResolvedValue({ ...mockItems[0], collectionId: 2 }) } as unknown as ReturnType<typeof useData>);
      await renderWithRouter('/collections/1/items/1');
      expect(await screen.findByText('Item not found')).toBeInTheDocument();
      expect(mockRecordView).not.toHaveBeenCalled();
    });

    it.each(['1', 'new'])('waits for category navigation without losing the item route: %s', async itemId => {
      vi.mocked(useData).mockReturnValue({ ...mockDataContext, categoriesLoading: true } as unknown as ReturnType<typeof useData>);
      await renderWithRouter(`/collections/1/items/${itemId}`);
      expect(screen.getByText('Loading categories…')).toBeInTheDocument();
      if (itemId === '1') expect(screen.getByText('Test Item')).toBeInTheDocument();
    });

    it('rejects a category outside the collection when adding an item', async () => {
      await renderWithRouter('/collections/1/items/new?categoryId=99');
      expect(screen.getByRole('alert')).toHaveTextContent('Category not found');
    });

    it.each([null, 1])('returns to the relevant location when closing the template chooser: %s', async category => {
      await renderWithRouter(`/collections/1/items/new${category ? '?categoryId=1' : ''}`);
      await screen.findByText('Start from scratch');
      await userEvent.click(screen.getByRole('button', { name: 'Close' }));
      expect(mockNavigate).toHaveBeenCalledWith(category ? '/collections/1/categories/1' : '/collections/1');
    });

    it('creates an uncategorized item and returns to its collection', async () => {
      await renderWithRouter('/collections/1/items/new');
      await userEvent.click(await screen.findByText('Start from scratch'));
      await userEvent.type(screen.getByLabelText('Name'), 'Loose item');
      await userEvent.click(screen.getByRole('button', { name: 'Create Item' }));
      expect(mockDataContext.addItem).toHaveBeenCalledWith(expect.objectContaining({ collectionId: 1, categoryId: null }));
      expect(mockNavigate).toHaveBeenCalledWith('/collections/1');
    });

    it('keeps collection and category navigation available from item details', async () => {
      await renderWithRouter('/collections/1/items/1');
      await userEvent.click(screen.getByRole('button', { name: 'All Root Category' }));
      expect(mockNavigate).toHaveBeenLastCalledWith('/collections/1/categories/1');
      await userEvent.click(screen.getByRole('button', { name: 'Go back' }));
      expect(mockNavigate).toHaveBeenLastCalledWith('/collections/1');
    });

    it('returns to the newly selected category after creating an item', async () => {
      await renderWithRouter('/collections/1/items/new?categoryId=1');
      await userEvent.click(await screen.findByText('Start from scratch'));
      await userEvent.type(screen.getByLabelText('Name'), 'Uncategorized draft');
      await userEvent.selectOptions(screen.getByLabelText('Category'), '');
      await userEvent.click(screen.getByRole('button', { name: 'Create Item' }));
      expect(mockNavigate).toHaveBeenCalledWith('/collections/1');
    });

    it('shows a recoverable preview failure after saving the changed property schema', async () => {
      vi.mocked(bulkUpdatesApi.preview).mockRejectedValueOnce(new Error('Preview offline'));
      await renderWithRouter('/collections/1/items/1');
      await userEvent.click(screen.getByRole('button', { name: 'Edit' }));
      const property = screen.getByPlaceholderText('Name');
      await userEvent.clear(property);
      await userEvent.type(property, 'Shade');
      await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
      expect(await screen.findByRole('alert')).toHaveTextContent('Item saved; related items could not be checked');
      expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument();
      await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
      expect(await screen.findByRole('dialog', { name: 'Bulk property update' })).toBeInTheDocument();
      await userEvent.click(screen.getByRole('button', { name: 'Skip' }));
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(mockDataContext.updateItem).toHaveBeenCalledOnce();
    });
  });

  describe('snapshots', () => {
    it('should match snapshot for existing item', async () => {
      const { container } = await renderWithRouter('/collections/1/items/1');
      expect({
        layout: container.firstElementChild?.className,
        headings: screen.getAllByRole('heading').map(heading => heading.textContent),
        categoryNavigation: screen.getByRole('navigation', { name: 'Category navigation' }).className,
        expanded: screen.getByRole('button', { name: 'Collapse categories' }).getAttribute('aria-expanded'),
      }).toMatchSnapshot();
    });
  });
});
