import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CategoryNav from '../src/components/category/CategoryNav';
import * as DataContext from '../src/contexts/useData';
import { createMockCategory, createMockCollection, createMockDataContextValue, createMockItem } from './testUtils';

// Mock the useData hook
vi.mock('../src/contexts/useData', async () => {
  const actual = await vi.importActual<typeof import('../src/contexts/DataContext')>('../src/contexts/DataContext');
  return {
    ...actual,
    useData: vi.fn(),
  };
});

describe('CategoryNav', () => {
  // Camera hierarchy:
  //   1: Rangefinders (root)  -> children: 2 (35mm Film), 3 (Medium Format)
  //   2: 35mm Film            -> children: 4 (Leica)
  //   3: Medium Format        -> no children (leaf)
  //   4: Leica                -> no children (leaf)
  //   5: SLR Cameras (root)   -> no children
  const mockCategories = [
    createMockCategory({ categoryId: 1, name: 'Rangefinders', parentCategoryId: null }),
    createMockCategory({ categoryId: 2, name: '35mm Film', parentCategoryId: 1 }),
    createMockCategory({ categoryId: 3, name: 'Medium Format', parentCategoryId: 1 }),
    createMockCategory({ categoryId: 4, name: 'Leica', parentCategoryId: 2 }),
    createMockCategory({ categoryId: 5, name: 'SLR Cameras', parentCategoryId: null }),
  ];

  beforeEach(() => {
    vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
      categories: mockCategories,
      addCategory: vi.fn(async () => 6),
      addCollection: vi.fn(async () => createMockCollection()),
    }));
  });

  /** Helper: query within the .categoryNav__list container to avoid modal duplicates */
  function getNavList(container: HTMLElement) {
    const list = container.querySelector('.categoryNav__list');
    if (!list) throw new Error('categoryNav__list not found');
    return within(list as HTMLElement);
  }

  describe('root level', () => {
    it('renders root categories', () => {
      const { container } = render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={() => {}} />
      );
      const list = getNavList(container);
      expect(list.getByText('Rangefinders')).toBeInTheDocument();
      expect(list.getByText('SLR Cameras')).toBeInTheDocument();
    });

    it('does not show child categories', () => {
      const { container } = render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={() => {}} />
      );
      const list = getNavList(container);
      expect(list.queryByText('35mm Film')).not.toBeInTheDocument();
      expect(list.queryByText('Medium Format')).not.toBeInTheDocument();
      expect(list.queryByText('Leica')).not.toBeInTheDocument();
    });

    it('shows chevron on categories with children', () => {
      const { container } = render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={() => {}} />
      );
      // Rangefinders has children, so its row should contain a chevron
      const rows = container.querySelectorAll('.categoryNav__row');
      const rangefinderRow = Array.from(rows).find(r => r.textContent?.includes('Rangefinders'));
      expect(rangefinderRow?.querySelector('.categoryNav__chevron')).toBeTruthy();

      // SLR Cameras has no children, so no chevron
      const slrRow = Array.from(rows).find(r => r.textContent?.includes('SLR Cameras'));
      expect(slrRow?.querySelector('.categoryNav__chevron')).toBeFalsy();
    });

    it('does not show breadcrumb', () => {
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={() => {}} />
      );
      expect(screen.queryByLabelText('Category breadcrumb')).not.toBeInTheDocument();
    });

    it('does not show back button', () => {
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={() => {}} />
      );
      expect(screen.queryByLabelText('Go back')).not.toBeInTheDocument();
    });

    it('shows header with title and add button', () => {
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={() => {}} />
      );
      expect(screen.getByText('Categories')).toBeInTheDocument();
      expect(screen.getByLabelText('Add category')).toBeInTheDocument();
    });
  });

  describe('drilled into category (selectedCategoryId=1, which has children)', () => {
    it('shows children (35mm Film, Medium Format)', () => {
      const { container } = render(
        <CategoryNav categories={mockCategories} selectedCategoryId={1} onSelect={() => {}} />
      );
      const list = getNavList(container);
      expect(list.getByText('35mm Film')).toBeInTheDocument();
      expect(list.getByText('Medium Format')).toBeInTheDocument();
    });

    it('shows "All Rangefinders" row as active', () => {
      const { container } = render(
        <CategoryNav categories={mockCategories} selectedCategoryId={1} onSelect={() => {}} />
      );
      const list = getNavList(container);
      expect(list.getByText('All Rangefinders')).toBeInTheDocument();
      const activeRow = container.querySelector('.categoryNav__row--active');
      expect(activeRow).toBeTruthy();
      expect(activeRow?.textContent).toContain('All Rangefinders');
    });

    it('shows breadcrumb', () => {
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={1} onSelect={() => {}} />
      );
      expect(screen.getByLabelText('Category breadcrumb')).toBeInTheDocument();
    });

    it('shows back button', () => {
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={1} onSelect={() => {}} />
      );
      expect(screen.getByLabelText('Go back')).toBeInTheDocument();
    });

    it('does not show root siblings (SLR Cameras)', () => {
      const { container } = render(
        <CategoryNav categories={mockCategories} selectedCategoryId={1} onSelect={() => {}} />
      );
      const list = getNavList(container);
      expect(list.queryByText('SLR Cameras')).not.toBeInTheDocument();
    });
  });

  describe('deep drill (selectedCategoryId=2, child of 1)', () => {
    it('shows grandchildren (Leica)', () => {
      const { container } = render(
        <CategoryNav categories={mockCategories} selectedCategoryId={2} onSelect={() => {}} />
      );
      const list = getNavList(container);
      expect(list.getByText('Leica')).toBeInTheDocument();
    });

    it('shows "All 35mm Film" row', () => {
      const { container } = render(
        <CategoryNav categories={mockCategories} selectedCategoryId={2} onSelect={() => {}} />
      );
      const list = getNavList(container);
      expect(list.getByText('All 35mm Film')).toBeInTheDocument();
    });

    it('full breadcrumb path contains All, Rangefinders, 35mm Film', () => {
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={2} onSelect={() => {}} />
      );
      const breadcrumb = screen.getByLabelText('Category breadcrumb');
      expect(breadcrumb.textContent).toContain('All');
      expect(breadcrumb.textContent).toContain('Rangefinders');
      expect(breadcrumb.textContent).toContain('35mm Film');
    });
  });

  describe('leaf category (selectedCategoryId=3, leaf child of 1)', () => {
    it('stays at parent level - shows siblings (35mm Film, Medium Format)', () => {
      const { container } = render(
        <CategoryNav categories={mockCategories} selectedCategoryId={3} onSelect={() => {}} />
      );
      const list = getNavList(container);
      // Should show siblings at the Rangefinders level
      expect(list.getByText('35mm Film')).toBeInTheDocument();
      expect(list.getByText('Medium Format')).toBeInTheDocument();
      // Should show "All Rangefinders" header
      expect(list.getByText('All Rangefinders')).toBeInTheDocument();
    });
  });

  describe('interaction', () => {
    it('click category row calls onSelect with categoryId', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      const { container } = render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={handleSelect} />
      );
      const list = getNavList(container);
      await user.click(list.getByText('Rangefinders'));
      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('click child category calls onSelect with child id', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      const { container } = render(
        <CategoryNav categories={mockCategories} selectedCategoryId={1} onSelect={handleSelect} />
      );
      const list = getNavList(container);
      await user.click(list.getByText('35mm Film'));
      expect(handleSelect).toHaveBeenCalledWith(2);
    });
  });

  describe('breadcrumb navigation', () => {
    it('click "All" breadcrumb calls onSelect(null)', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={1} onSelect={handleSelect} />
      );
      await user.click(screen.getByLabelText('Navigate to All'));
      expect(handleSelect).toHaveBeenCalledWith(null);
    });

    it('click ancestor breadcrumb calls onSelect(ancestorId)', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={2} onSelect={handleSelect} />
      );
      await user.click(screen.getByLabelText('Navigate to Rangefinders'));
      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('breadcrumb links have aria-label="Navigate to [Name]"', () => {
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={2} onSelect={() => {}} />
      );
      expect(screen.getByLabelText('Navigate to All')).toBeInTheDocument();
      expect(screen.getByLabelText('Navigate to Rangefinders')).toBeInTheDocument();
    });
  });

  describe('back button', () => {
    it('from first drill level, back calls onSelect(null)', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={1} onSelect={handleSelect} />
      );
      await user.click(screen.getByLabelText('Go back'));
      expect(handleSelect).toHaveBeenCalledWith(null);
    });

    it('from second drill level, back calls onSelect(parentId)', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={2} onSelect={handleSelect} />
      );
      await user.click(screen.getByLabelText('Go back'));
      expect(handleSelect).toHaveBeenCalledWith(1);
    });
  });

  describe('collapse', () => {
    it('collapse button shown when onCollapse provided', () => {
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={() => {}} onCollapse={() => {}} />
      );
      expect(screen.getByLabelText('Collapse categories')).toBeInTheDocument();
    });

    it('not shown when onCollapse not provided', () => {
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={() => {}} />
      );
      expect(screen.queryByLabelText('Collapse categories')).not.toBeInTheDocument();
    });

    it('click calls onCollapse', async () => {
      const user = userEvent.setup();
      const handleCollapse = vi.fn();
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={() => {}} onCollapse={handleCollapse} />
      );
      await user.click(screen.getByLabelText('Collapse categories'));
      expect(handleCollapse).toHaveBeenCalled();
    });
  });

  describe('edit', () => {
    it('edit button visible on hover (has aria-label="Edit [Name]")', () => {
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={() => {}} />
      );
      expect(screen.getByLabelText('Edit Rangefinders')).toBeInTheDocument();
      expect(screen.getByLabelText('Edit SLR Cameras')).toBeInTheDocument();
    });

    it('clicking edit button opens CategoryEditorModal with that category', async () => {
      const user = userEvent.setup();
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={() => {}} />
      );
      await user.click(screen.getByLabelText('Edit Rangefinders'));
      // Modal should open - look for the dialog
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    it('clicking add button opens CategoryEditorModal for new category', async () => {
      const user = userEvent.setup();
      render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={() => {}} />
      );
      await user.click(screen.getByLabelText('Add category'));
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });
  });

  describe('system category filtering', () => {
    it('system categories with no items are hidden', () => {
      const categoriesWithSystem = [
        ...mockCategories,
        createMockCategory({ categoryId: 10, name: 'System Cat', parentCategoryId: null, isSystem: true }),
      ];

      vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
        categories: categoriesWithSystem,
        items: [],
      }));

      render(
        <CategoryNav categories={categoriesWithSystem} selectedCategoryId={null} onSelect={() => {}} />
      );
      expect(screen.queryByText('System Cat')).not.toBeInTheDocument();
    });

    it('system categories with items are shown', () => {
      const categoriesWithSystem = [
        ...mockCategories,
        createMockCategory({ categoryId: 10, name: 'System Cat', parentCategoryId: null, isSystem: true }),
      ];

      vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
        categories: categoriesWithSystem,
        items: [createMockItem({ id: 100, categoryId: 10 })],
      }));

      render(
        <CategoryNav categories={categoriesWithSystem} selectedCategoryId={null} onSelect={() => {}} />
      );
      expect(screen.getByText('System Cat')).toBeInTheDocument();
    });
  });

  describe('loading/error states', () => {
    it('shows loading message when categoriesLoading', () => {
      vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
        categoriesLoading: true,
      }));

      render(
        <CategoryNav categories={[]} selectedCategoryId={null} onSelect={() => {}} />
      );
      expect(screen.getByText('Loading categories...')).toBeInTheDocument();
    });

    it('shows error message when categoriesError', () => {
      vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
        categoriesError: 'Failed to fetch categories: Internal Server Error',
      }));

      render(
        <CategoryNav categories={[]} selectedCategoryId={null} onSelect={() => {}} />
      );
      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText(/Error loading categories:/)).toBeInTheDocument();
      expect(screen.getByText(/Failed to fetch categories: Internal Server Error/)).toBeInTheDocument();
    });
  });

  describe('snapshots', () => {
    it('root level snapshot', () => {
      const { container } = render(
        <CategoryNav categories={mockCategories} selectedCategoryId={null} onSelect={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });

    it('drilled level snapshot', () => {
      const { container } = render(
        <CategoryNav categories={mockCategories} selectedCategoryId={1} onSelect={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });
  });
});
