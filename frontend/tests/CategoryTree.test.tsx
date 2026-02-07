import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CategoryTree from '../src/components/category/CategoryTree';
import * as DataContext from '../src/contexts/DataContext';
import { createMockCategory, createMockCollection, createMockDataContextValue } from './testUtils';

// Mock the useData hook
vi.mock('../src/contexts/DataContext', async () => {
  const actual = await vi.importActual<typeof import('../src/contexts/DataContext')>('../src/contexts/DataContext');
  return {
    ...actual,
    useData: vi.fn(),
  };
});

describe('CategoryTree', () => {
  const mockCategories = [
    createMockCategory({ categoryId: 1, name: 'Root 1', description: 'Root 1 desc', parentCategoryId: null }),
    createMockCategory({ categoryId: 2, name: 'Child 1-1', description: 'Child 1-1 desc', parentCategoryId: 1 }),
    createMockCategory({ categoryId: 3, name: 'Child 1-2', description: 'Child 1-2 desc', parentCategoryId: 1 }),
    createMockCategory({ categoryId: 4, name: 'Grandchild 1-1-1', description: 'Grandchild desc', parentCategoryId: 2 }),
    createMockCategory({ categoryId: 5, name: 'Root 2', description: 'Root 2 desc', parentCategoryId: null }),
  ];

  // Shared expanded state for tests that need to verify toggle behavior
  let expandedCategoryIds = new Set([1, 5]); // Root categories expanded by default
  const toggleCategoryExpanded = vi.fn((categoryId: number) => {
    expandedCategoryIds = new Set(expandedCategoryIds);
    if (expandedCategoryIds.has(categoryId)) {
      expandedCategoryIds.delete(categoryId);
    } else {
      expandedCategoryIds.add(categoryId);
    }
  });

  beforeEach(() => {
    // Reset expanded state
    expandedCategoryIds = new Set([1, 5]);
    toggleCategoryExpanded.mockClear();

    // Default mock: not loading, no error
    vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
      categories: mockCategories,
      addCategory: vi.fn(async () => 6),
      addCollection: vi.fn(async () => createMockCollection()),
      expandedCategoryIds,
      toggleCategoryExpanded,
    }));
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

    it('should call toggleCategoryExpanded when clicking collapse button', async () => {
      const user = userEvent.setup();

      render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      // Children should be visible initially (Root 1 is expanded)
      expect(screen.getAllByText('Child 1-1').length).toBeGreaterThanOrEqual(1);

      // Click collapse button for Root 1
      const collapseButton = screen.getByLabelText('Collapse Root 1');
      await user.click(collapseButton);

      // Verify toggle was called with the correct category ID
      expect(toggleCategoryExpanded).toHaveBeenCalledWith(1);
    });

    it('should call toggleCategoryExpanded when clicking expand button', async () => {
      const user = userEvent.setup();

      // Start with Root 1 collapsed
      vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
        categories: mockCategories,
        expandedCategoryIds: new Set([5]), // Only Root 2 expanded, Root 1 collapsed
        toggleCategoryExpanded,
      }));

      render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      // Click expand button for Root 1
      const expandButton = screen.getByLabelText('Expand Root 1');
      await user.click(expandButton);

      // Verify toggle was called with the correct category ID
      expect(toggleCategoryExpanded).toHaveBeenCalledWith(1);
    });

    it('should call toggleCategoryExpanded for nested categories', async () => {
      const user = userEvent.setup();

      render(
        <CategoryTree
          categories={mockCategories}
          selectedCategoryId={null}
          onSelect={() => {}}
        />
      );

      // Grandchild should not be visible (Child 1-1 is not expanded by default)
      const grandchildElements = screen.queryAllByText('Grandchild 1-1-1');
      const treeGrandchild = grandchildElements.find(el => el.classList.contains('categoryTree__item'));
      expect(treeGrandchild).toBeFalsy();

      // Expand Child 1-1
      const expandButton = screen.getByLabelText('Expand Child 1-1');
      await user.click(expandButton);

      // Verify toggle was called with the correct category ID
      expect(toggleCategoryExpanded).toHaveBeenCalledWith(2);
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
      const orphanedCategories = [
        createMockCategory({ categoryId: 1, name: 'Root', description: 'Desc', parentCategoryId: null }),
        createMockCategory({ categoryId: 2, name: 'Orphan', description: 'Desc', parentCategoryId: 999 }), // Non-existent parent
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
      vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
        categoriesLoading: true,
      }));

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
      vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
        categoriesError: 'Failed to fetch categories: Internal Server Error',
      }));

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

