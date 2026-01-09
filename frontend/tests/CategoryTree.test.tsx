import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CategoryTree from '../src/CategoryTree';
import type { Category } from '../src/types';
import * as DataContext from '../src/DataContext';

// Mock the useData hook
vi.mock('../src/DataContext', async () => {
  const actual = await vi.importActual<typeof import('../src/DataContext')>('../src/DataContext');
  return {
    ...actual,
    useData: vi.fn(),
  };
});

describe('CategoryTree', () => {
  const mockCategories: Category[] = [
    { tenantId: 1, categoryId: 1, name: 'Root 1', description: 'Root 1 desc', parentCategoryId: null, isSystem: false },
    { tenantId: 1, categoryId: 2, name: 'Child 1-1', description: 'Child 1-1 desc', parentCategoryId: 1, isSystem: false },
    { tenantId: 1, categoryId: 3, name: 'Child 1-2', description: 'Child 1-2 desc', parentCategoryId: 1, isSystem: false },
    { tenantId: 1, categoryId: 4, name: 'Grandchild 1-1-1', description: 'Grandchild desc', parentCategoryId: 2, isSystem: false },
    { tenantId: 1, categoryId: 5, name: 'Root 2', description: 'Root 2 desc', parentCategoryId: null, isSystem: false },
  ];

  beforeEach(() => {
    // Default mock: not loading, no error
    vi.mocked(DataContext.useData).mockReturnValue({
      currentCollection: null,
      setCurrentCollection: vi.fn(),
      collections: [],
      collectionsLoading: false,
      collectionsError: null,
      loadCollections: vi.fn(async () => {}),
      addCollection: vi.fn(async () => ({ collectionId: 1, tenantId: 1, name: '', description: '', heroImageUrl: null, slug: '' })),
      updateCollection: vi.fn(async () => {}),
      deleteCollection: vi.fn(async () => {}),
      categories: mockCategories,
      categoriesLoading: false,
      categoriesError: null,
      loadCategoriesForCollection: vi.fn(async () => {}),
      addCategory: vi.fn(async () => 6),
      updateCategory: vi.fn(async () => {}),
      deleteCategory: vi.fn(async () => {}),
      items: [],
      itemsLoading: false,
      itemsError: null,
      loadItemsForCategory: vi.fn(async () => {}),
      addItem: vi.fn(async () => 0),
      updateItem: vi.fn(async () => {}),
      deleteItem: vi.fn(async () => {}),
      propertyCategorySuggestions: [],
      propertyNameSuggestions: [],
      loadPropertySuggestions: vi.fn(async () => {}),
      syncPropertySuggestions: vi.fn(async () => {}),
      addLocalCategorySuggestion: vi.fn(),
      addLocalNameSuggestion: vi.fn(),
    });
  });

  describe('snapshots', () => {
    it('should render empty tree', () => {
      const { container } = render(
        <CategoryTree categories={[]} selectedCategoryId={null} onSelect={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });

    it('should render tree with categories', () => {
      const { container } = render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );
      expect(container).toMatchSnapshot();
    });

    it('should render with selected category', () => {
      const { container } = render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={2}
          onSelect={() => {}}
        />
      );
      expect(container).toMatchSnapshot();
    });
  });

  describe('functionality', () => {
    it('should render root categories', () => {
      render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      // Use getAllByText and check within category tree
      expect(screen.getAllByText('Root 1').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText('Root 2').length).toBeGreaterThanOrEqual(1);
    });

    it('should render children of expanded root categories', () => {
      render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      // Root categories are expanded by default
      expect(screen.getAllByText('Child 1-1').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText('Child 1-2').length).toBeGreaterThanOrEqual(1);
    });

    it('should call onSelect when clicking a category', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();

      render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={null}
          onSelect={handleSelect}
        />
      );

      // Click the categoryTree__item button (not other elements with same text)
      const root1Button = screen.getAllByText('Root 1').find(el => el.classList.contains('categoryTree__item'));
      expect(root1Button).toBeTruthy();
      await user.click(root1Button!);

      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('should collapse expanded category when clicking toggle', async () => {
      const user = userEvent.setup();

      render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      // Children should be visible initially
      expect(screen.getAllByText('Child 1-1').length).toBeGreaterThanOrEqual(1);

      // Click collapse button for Root 1
      const collapseButton = screen.getByLabelText('Collapse Root 1');
      await user.click(collapseButton);

      // Children should be hidden from tree (may still appear in modal's parent selector)
      const child11Elements = screen.queryAllByText('Child 1-1');
      const treeChild = child11Elements.find(el => el.classList.contains('categoryTree__item'));
      expect(treeChild).toBeFalsy();
    });

    it('should expand collapsed category when clicking toggle', async () => {
      const user = userEvent.setup();

      render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      // First collapse
      const collapseButton = screen.getByLabelText('Collapse Root 1');
      await user.click(collapseButton);

      // Verify collapsed
      let child11Elements = screen.queryAllByText('Child 1-1');
      let treeChild = child11Elements.find(el => el.classList.contains('categoryTree__item'));
      expect(treeChild).toBeFalsy();

      // Then expand
      const expandButton = screen.getByLabelText('Expand Root 1');
      await user.click(expandButton);

      // Verify expanded
      child11Elements = screen.queryAllByText('Child 1-1');
      treeChild = child11Elements.find(el => el.classList.contains('categoryTree__item'));
      expect(treeChild).toBeTruthy();
    });

    it('should show nested grandchildren when parent is expanded', async () => {
      const user = userEvent.setup();

      render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      // Grandchild should not be visible (Child 1-1 is not expanded by default)
      let grandchildElements = screen.queryAllByText('Grandchild 1-1-1');
      let treeGrandchild = grandchildElements.find(el => el.classList.contains('categoryTree__item'));
      expect(treeGrandchild).toBeFalsy();

      // Expand Child 1-1
      const expandButton = screen.getByLabelText('Expand Child 1-1');
      await user.click(expandButton);

      grandchildElements = screen.queryAllByText('Grandchild 1-1-1');
      treeGrandchild = grandchildElements.find(el => el.classList.contains('categoryTree__item'));
      expect(treeGrandchild).toBeTruthy();
    });

    it('should highlight selected category', () => {
      render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={1}
          onSelect={() => {}}
        />
      );

      // Use getAllByText and find the one with the active class (there may be duplicates in modal)
      const buttons = screen.getAllByText('Root 1');
      const selectedButton = buttons.find(b => b.classList.contains('categoryTree__item--active'));
      expect(selectedButton).toBeTruthy();
    });

    it('should handle categories with orphaned parent references', () => {
      const orphanedCategories: Category[] = [
        { tenantId: 1, categoryId: 1, name: 'Root', description: 'Desc', parentCategoryId: null, isSystem: false },
        { tenantId: 1, categoryId: 2, name: 'Orphan', description: 'Desc', parentCategoryId: 999, isSystem: false }, // Non-existent parent
      ];

      render(
        <CategoryTree
          categories={orphanedCategories}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      // Orphan should be treated as root (both should appear in tree)
      expect(screen.getAllByText('Root').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText('Orphan').length).toBeGreaterThanOrEqual(1);
    });

    it('should handle empty categories array for initial expanded state', () => {
      render(
        <CategoryTree
          categories={[]}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      expect(screen.getByText('Categories')).toBeInTheDocument();
    });

    it('should render title', () => {
      render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      expect(screen.getByText('Categories')).toBeInTheDocument();
    });
  });

  describe('loading and error states', () => {
    it('should display loading message when categories are loading', () => {
      vi.mocked(DataContext.useData).mockReturnValue({
        currentCollection: null,
        setCurrentCollection: vi.fn(),
        collections: [],
        collectionsLoading: false,
        collectionsError: null,
        loadCollections: vi.fn(async () => {}),
        addCollection: vi.fn(async () => ({ collectionId: 1, tenantId: 1, name: '', description: '', heroImageUrl: null, slug: '' })),
        updateCollection: vi.fn(async () => {}),
        deleteCollection: vi.fn(async () => {}),
        categories: [],
        categoriesLoading: true,
        categoriesError: null,
        loadCategoriesForCollection: vi.fn(async () => {}),
        addCategory: vi.fn(async () => 0),
        updateCategory: vi.fn(async () => {}),
        deleteCategory: vi.fn(async () => {}),
        items: [],
        itemsLoading: false,
        itemsError: null,
        loadItemsForCategory: vi.fn(async () => {}),
        addItem: vi.fn(async () => 0),
        updateItem: vi.fn(async () => {}),
        deleteItem: vi.fn(async () => {}),
        propertyCategorySuggestions: [],
        propertyNameSuggestions: [],
        loadPropertySuggestions: vi.fn(async () => {}),
        syncPropertySuggestions: vi.fn(async () => {}),
        addLocalCategorySuggestion: vi.fn(),
        addLocalNameSuggestion: vi.fn(),
      });

      render(
        <CategoryTree
          categories={[]}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      expect(screen.getByText('Loading categories...')).toBeInTheDocument();
    });

    it('should display error message when categories fail to load', () => {
      vi.mocked(DataContext.useData).mockReturnValue({
        currentCollection: null,
        setCurrentCollection: vi.fn(),
        collections: [],
        collectionsLoading: false,
        collectionsError: null,
        loadCollections: vi.fn(async () => {}),
        addCollection: vi.fn(async () => ({ collectionId: 1, tenantId: 1, name: '', description: '', heroImageUrl: null, slug: '' })),
        updateCollection: vi.fn(async () => {}),
        deleteCollection: vi.fn(async () => {}),
        categories: [],
        categoriesLoading: false,
        categoriesError: 'Failed to fetch categories: Internal Server Error',
        loadCategoriesForCollection: vi.fn(async () => {}),
        addCategory: vi.fn(async () => 0),
        updateCategory: vi.fn(async () => {}),
        deleteCategory: vi.fn(async () => {}),
        items: [],
        itemsLoading: false,
        itemsError: null,
        loadItemsForCategory: vi.fn(async () => {}),
        addItem: vi.fn(async () => 0),
        updateItem: vi.fn(async () => {}),
        deleteItem: vi.fn(async () => {}),
        propertyCategorySuggestions: [],
        propertyNameSuggestions: [],
        loadPropertySuggestions: vi.fn(async () => {}),
        syncPropertySuggestions: vi.fn(async () => {}),
        addLocalCategorySuggestion: vi.fn(),
        addLocalNameSuggestion: vi.fn(),
      });

      render(
        <CategoryTree
          categories={[]}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText(/Error loading categories:/)).toBeInTheDocument();
      expect(screen.getByText(/Failed to fetch categories: Internal Server Error/)).toBeInTheDocument();
    });
  });
});

