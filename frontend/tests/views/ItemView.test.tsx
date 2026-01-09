import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import ItemView from '../../src/views/ItemView';
import { useData } from '../../src/DataContext';
import type { Collection, Category, Item } from '../../src/types';

vi.mock('../../src/DataContext', () => ({
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
        <Route path="/collections/:collectionId/items/:itemId" element={<ItemView />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('ItemView', () => {
  const mockCollections: Collection[] = [
    { collectionId: 1, tenantId: 1, name: 'Test Collection', description: 'Test desc', heroImageUrl: null, slug: 'test' },
  ];

  const mockCategories: Category[] = [
    { tenantId: 1, categoryId: 1, collectionId: 1, name: 'Root Category', description: 'Root desc', parentCategoryId: null, isSystem: false },
  ];

  const mockItems: Item[] = [
    {
      id: 1,
      tenantId: 1,
      collectionId: 1,
      categoryId: 1,
      name: 'Test Item',
      summary: 'Test summary',
      description: 'Test description',
      properties: [{ category: 'General', name: 'Color', value: 'Blue' }],
      images: [{ url: 'https://example.com/img.jpg', alt: 'Test image' }],
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
    loadItemById: vi.fn(async () => null),
    addItem: vi.fn(async () => 2),
    updateItem: vi.fn(async () => {}),
    deleteItem: vi.fn(async () => {}),
    loadPropertySuggestions: vi.fn(),
    syncPropertySuggestions: vi.fn(),
    propertyCategorySuggestions: [],
    propertyNameSuggestions: [],
    addLocalCategorySuggestion: vi.fn(),
    addLocalNameSuggestion: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    (useData as ReturnType<typeof vi.fn>).mockReturnValue(mockDataContext);
  });

  describe('viewing existing item', () => {
    it('should display item details', () => {
      renderWithRouter('/collections/1/items/1');

      expect(screen.getByText('Test Item')).toBeInTheDocument();
      expect(screen.getByText('Test description')).toBeInTheDocument();
    });

    it('should show edit button', () => {
      renderWithRouter('/collections/1/items/1');

      expect(screen.getByText('Edit')).toBeInTheDocument();
    });

    it('should show back button', () => {
      renderWithRouter('/collections/1/items/1');

      expect(screen.getByText('← Back to items')).toBeInTheDocument();
    });

    it('should navigate back to category when back is clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1/items/1');

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

      renderWithRouter('/collections/1/items/999');

      await waitFor(() => {
        expect(screen.getByText('Item not found')).toBeInTheDocument();
      });
    });
  });

  describe('editing item', () => {
    it('should show editor when edit is clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1/items/1');

      await user.click(screen.getByText('Edit'));

      expect(screen.getByLabelText('Name')).toBeInTheDocument();
    });

    it('should call updateItem when saving', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1/items/1');

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
      renderWithRouter('/collections/1/items/1');

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
      
      renderWithRouter('/collections/1/items/1');

      await user.click(screen.getByText('Edit'));
      await user.click(screen.getByText('Delete'));

      expect(mockDataContext.deleteItem).toHaveBeenCalledWith(1);
      expect(mockNavigate).toHaveBeenCalledWith('/collections/1/categories/1');
    });
  });

  describe('creating new item', () => {
    it('should show editor for new item', () => {
      renderWithRouter('/collections/1/items/new?categoryId=1');

      expect(screen.getByText('Add New Item')).toBeInTheDocument();
    });

    it('should call addItem when creating', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1/items/new?categoryId=1');

      await user.type(screen.getByLabelText('Name'), 'New Item');
      await user.click(screen.getByText('Create Item'));

      expect(mockDataContext.addItem).toHaveBeenCalled();
    });

    it('should navigate back after creating', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1/items/new?categoryId=1');

      await user.type(screen.getByLabelText('Name'), 'New Item');
      await user.click(screen.getByText('Create Item'));

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/collections/1/categories/1');
      });
    });

    it('should navigate back when cancelling new item', async () => {
      const user = userEvent.setup();
      renderWithRouter('/collections/1/items/new?categoryId=1');

      // Find the Cancel button in the editor form
      const cancelButton = screen.getByRole('button', { name: 'Cancel' });
      await user.click(cancelButton);

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/collections/1/categories/1');
      });
    });
  });

  describe('deep linking', () => {
    it('should load collection data when navigating directly to item with empty collections', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        collections: [],
        currentCollection: null,
      });

      renderWithRouter('/collections/1/items/1');

      expect(mockDataContext.loadCollections).toHaveBeenCalled();
    });

    it('should redirect to collections if collection not found', async () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: null,
        collections: [{ collectionId: 99, tenantId: 1, name: 'Other', description: '', heroImageUrl: null, slug: 'other' }],
      });

      renderWithRouter('/collections/999/items/1');

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/collections', { replace: true });
      });
    });
  });

  describe('loading states', () => {
    it('should show loading state when collections are loading', () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        collectionsLoading: true,
      });

      renderWithRouter('/collections/1/items/1');

      expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('should show collection not found when no current collection', async () => {
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        currentCollection: null,
        collections: [{ ...mockCollections[0], collectionId: 999 }], // Different collection ID
      });

      renderWithRouter('/collections/1/items/1');

      // When collection is not found, it redirects to /collections
      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/collections', { replace: true });
      });
    });
  });
});
