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
    { tenantId: 1, categoryId: 1, name: 'Root 1', description: 'Root 1 desc', parentCategoryId: null },
    { tenantId: 1, categoryId: 2, name: 'Child 1-1', description: 'Child 1-1 desc', parentCategoryId: 1 },
    { tenantId: 1, categoryId: 3, name: 'Child 1-2', description: 'Child 1-2 desc', parentCategoryId: 1 },
    { tenantId: 1, categoryId: 4, name: 'Grandchild 1-1-1', description: 'Grandchild desc', parentCategoryId: 2 },
    { tenantId: 1, categoryId: 5, name: 'Root 2', description: 'Root 2 desc', parentCategoryId: null },
  ];

  beforeEach(() => {
    // Default mock: not loading, no error
    vi.mocked(DataContext.useData).mockReturnValue({
      categories: mockCategories,
      categoriesLoading: false,
      categoriesError: null,
      items: [],
      collections: [],
      tenants: [],
      addItem: vi.fn(() => 0),
      updateItem: vi.fn(),
      deleteItem: vi.fn(),
      addCategory: vi.fn(),
      updateCategory: vi.fn(),
      deleteCategory: vi.fn(),
      addCollection: vi.fn(),
      updateCollection: vi.fn(),
      deleteCollection: vi.fn(),
      addTenant: vi.fn(),
      updateTenant: vi.fn(),
      deleteTenant: vi.fn(),
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

      expect(screen.getByText('Root 1')).toBeInTheDocument();
      expect(screen.getByText('Root 2')).toBeInTheDocument();
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
      expect(screen.getByText('Child 1-1')).toBeInTheDocument();
      expect(screen.getByText('Child 1-2')).toBeInTheDocument();
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

      await user.click(screen.getByText('Root 1'));

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
      expect(screen.getByText('Child 1-1')).toBeInTheDocument();

      // Click collapse button for Root 1
      const collapseButton = screen.getByLabelText('Collapse Root 1');
      await user.click(collapseButton);

      // Children should be hidden
      expect(screen.queryByText('Child 1-1')).not.toBeInTheDocument();
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

      expect(screen.queryByText('Child 1-1')).not.toBeInTheDocument();

      // Then expand
      const expandButton = screen.getByLabelText('Expand Root 1');
      await user.click(expandButton);

      expect(screen.getByText('Child 1-1')).toBeInTheDocument();
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
      expect(screen.queryByText('Grandchild 1-1-1')).not.toBeInTheDocument();

      // Expand Child 1-1
      const expandButton = screen.getByLabelText('Expand Child 1-1');
      await user.click(expandButton);

      expect(screen.getByText('Grandchild 1-1-1')).toBeInTheDocument();
    });

    it('should highlight selected category', () => {
      render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={1}
          onSelect={() => {}}
        />
      );

      const selectedButton = screen.getByText('Root 1');
      expect(selectedButton).toHaveClass('categoryTree__item--active');
    });

    it('should handle categories with orphaned parent references', () => {
      const orphanedCategories: Category[] = [
        { tenantId: 1, categoryId: 1, name: 'Root', description: 'Desc', parentCategoryId: null },
        { tenantId: 1, categoryId: 2, name: 'Orphan', description: 'Desc', parentCategoryId: 999 }, // Non-existent parent
      ];

      render(
        <CategoryTree
          categories={orphanedCategories}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      // Orphan should be treated as root
      expect(screen.getByText('Root')).toBeInTheDocument();
      expect(screen.getByText('Orphan')).toBeInTheDocument();
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
        categories: [],
        categoriesLoading: true,
        categoriesError: null,
        items: [],
        collections: [],
        tenants: [],
        addItem: vi.fn(() => 0),
        updateItem: vi.fn(),
        deleteItem: vi.fn(),
        addCategory: vi.fn(),
        updateCategory: vi.fn(),
        deleteCategory: vi.fn(),
        addCollection: vi.fn(),
        updateCollection: vi.fn(),
        deleteCollection: vi.fn(),
        addTenant: vi.fn(),
        updateTenant: vi.fn(),
        deleteTenant: vi.fn(),
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
        categories: [],
        categoriesLoading: false,
        categoriesError: 'Failed to fetch categories: Internal Server Error',
        items: [],
        collections: [],
        tenants: [],
        addItem: vi.fn(() => 0),
        updateItem: vi.fn(),
        deleteItem: vi.fn(),
        addCategory: vi.fn(),
        updateCategory: vi.fn(),
        deleteCategory: vi.fn(),
        addCollection: vi.fn(),
        updateCollection: vi.fn(),
        deleteCollection: vi.fn(),
        addTenant: vi.fn(),
        updateTenant: vi.fn(),
        deleteTenant: vi.fn(),
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

