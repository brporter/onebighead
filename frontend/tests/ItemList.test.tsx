import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ItemList from '../src/components/item/ItemList';
import type { Item, Category } from '../src/utils/types';
import { Visibility, UserFlag } from '../src/utils/types';

const mockBulkPublishItems = vi.fn();
const mockBulkUnpublishItems = vi.fn();
const mockPublishItem = vi.fn();
const mockUnpublishItem = vi.fn();

vi.mock('../src/contexts/useData', () => ({
  useData: () => ({
    bulkPublishItems: mockBulkPublishItems,
    bulkUnpublishItems: mockBulkUnpublishItems,
    publishItem: mockPublishItem,
    unpublishItem: mockUnpublishItem,
  }),
}));

describe('ItemList', () => {
  const createMockItems = (count: number): Item[] => {
    return Array.from({ length: count }, (_, i) => ({
      id: i + 1,
      workspaceId: 1,
      collectionId: 1,
      categoryId: 1,
      templateKey: null,
      name: `Item ${i + 1}`,
      summary: `Summary ${i + 1}`,
      description: `Description ${i + 1}`,
      properties: [],
      images: [],
      visibility: Visibility.Private,
      effectiveIsPublic: false,
      userFlag: UserFlag.Have,
    }));
  };

  const defaultCategories: Category[] = [{
    workspaceId: 1,
    collectionId: 1,
    categoryId: 1,
    name: 'Test Category',
    description: '',
    parentCategoryId: null,
    isSystem: false,
    visibility: Visibility.Private,
    effectiveIsPublic: false,
    itemTemplateIds: [],
  }];

  const defaultProps = {
    items: createMockItems(3),
    categories: defaultCategories,
    selectedId: null,
    onSelect: vi.fn(),
    pageIndex: 0,
    onPageChange: vi.fn(),
  };

  describe('snapshots', () => {
    it('should render empty list', () => {
      const { container } = render(
        <ItemList
          items={[]}
          categories={defaultCategories}
          selectedId={null}
          onSelect={() => {}}
          pageIndex={0}
          onPageChange={() => {}}
        />
      );
      expect(container).toMatchSnapshot();
    });

    it('should render list with items', () => {
      const { container } = render(<ItemList {...defaultProps} />);
      expect(container).toMatchSnapshot();
    });

    it('should render with selected item', () => {
      const { container } = render(<ItemList {...defaultProps} selectedId={2} />);
      expect(container).toMatchSnapshot();
    });

    it('should render with add button', () => {
      const { container } = render(<ItemList {...defaultProps} onAddItem={() => {}} />);
      expect(container).toMatchSnapshot();
    });

    it('should render with pagination on multiple pages', () => {
      const { container } = render(
        <ItemList {...defaultProps} items={createMockItems(50)} pageIndex={1} />
      );
      expect(container).toMatchSnapshot();
    });
  });

  describe('functionality', () => {
    it('should display "No items" when list is empty', () => {
      render(
        <ItemList
          items={[]}
          categories={defaultCategories}
          selectedId={null}
          onSelect={() => {}}
          pageIndex={0}
          onPageChange={() => {}}
        />
      );

      expect(screen.getByText('No items')).toBeInTheDocument();
    });

    it('should display item count', () => {
      render(<ItemList {...defaultProps} />);

      expect(screen.getByText('3 total')).toBeInTheDocument();
    });

    it('should display items', () => {
      render(<ItemList {...defaultProps} />);

      expect(screen.getByText('Item 1')).toBeInTheDocument();
      expect(screen.getByText('Summary 1')).toBeInTheDocument();
      expect(screen.getByText('Item 2')).toBeInTheDocument();
      expect(screen.getByText('Item 3')).toBeInTheDocument();
    });

    it('should call onSelect when clicking an item', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();

      render(<ItemList {...defaultProps} onSelect={handleSelect} />);

      const card = screen.getByRole('button', { name: 'Select Item 2' });
      await user.click(card);

      expect(handleSelect).toHaveBeenCalledWith(2);
    });

    it('should call onSelect when pressing Enter on an item', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();

      render(<ItemList {...defaultProps} onSelect={handleSelect} />);

      const card = screen.getByRole('button', { name: 'Select Item 1' });
      card.focus();
      await user.keyboard('{Enter}');

      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('should call onSelect when pressing Space on an item', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();

      render(<ItemList {...defaultProps} onSelect={handleSelect} />);

      const card = screen.getByRole('button', { name: 'Select Item 1' });
      card.focus();
      await user.keyboard(' ');

      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('should highlight selected item', () => {
      render(<ItemList {...defaultProps} selectedId={2} />);

      const selectedCard = screen.getByRole('button', { name: 'Select Item 2' });

      expect(selectedCard).toHaveClass('item-card--selected');
    });

    it('should show add button when onAddItem is provided', () => {
      const handleAddItem = vi.fn();

      render(<ItemList {...defaultProps} onAddItem={handleAddItem} />);

      expect(screen.getByText('+ Add Item')).toBeInTheDocument();
    });

    it('should call onAddItem when clicking add button', async () => {
      const user = userEvent.setup();
      const handleAddItem = vi.fn();

      render(<ItemList {...defaultProps} onAddItem={handleAddItem} />);

      await user.click(screen.getByText('+ Add Item'));

      expect(handleAddItem).toHaveBeenCalled();
    });

    it('should not show add button when onAddItem is null', () => {
      render(<ItemList {...defaultProps} onAddItem={null} />);

      expect(screen.queryByText('+ Add Item')).not.toBeInTheDocument();
    });

    it('should handle empty summary gracefully', () => {
      const items: Item[] = [{
        id: 1,
        workspaceId: 1,
        collectionId: 1,
        categoryId: 1,
        templateKey: null,
        name: 'Item without summary',
        summary: '',
        description: 'Desc',
        properties: [],
        images: [],
        visibility: Visibility.Private,
        effectiveIsPublic: false,
        userFlag: UserFlag.Have,
      }];

      render(<ItemList {...defaultProps} items={items} />);

      expect(screen.getByText('Item without summary')).toBeInTheDocument();
    });

    it('should not call onSelect for item with null id', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();

      const itemsWithNullId: Item[] = [{
        id: null,
        workspaceId: 1,
        collectionId: 1,
        categoryId: 1,
        templateKey: null,
        name: 'Item with null id',
        summary: 'Summary',
        description: 'Desc',
        properties: [],
        images: [],
        visibility: Visibility.Private,
        effectiveIsPublic: false,
        userFlag: UserFlag.Have,
      }];

      render(<ItemList {...defaultProps} items={itemsWithNullId} onSelect={handleSelect} />);

      const card = screen.getByRole('button', { name: 'Select Item with null id' });
      await user.click(card);

      expect(handleSelect).not.toHaveBeenCalled();
    });

    it('should not call onSelect when pressing Enter on item with null id', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();

      const itemsWithNullId: Item[] = [{
        id: null,
        workspaceId: 1,
        collectionId: 1,
        categoryId: 1,
        templateKey: null,
        name: 'Item with null id',
        summary: 'Summary',
        description: 'Desc',
        properties: [],
        images: [],
        visibility: Visibility.Private,
        effectiveIsPublic: false,
        userFlag: UserFlag.Have,
      }];

      render(<ItemList {...defaultProps} items={itemsWithNullId} onSelect={handleSelect} />);

      const card = screen.getByRole('button', { name: 'Select Item with null id' });
      card.focus();
      await user.keyboard('{Enter}');

      expect(handleSelect).not.toHaveBeenCalled();
    });
  });

  describe('pagination', () => {
    it('should display correct page info', () => {
      render(<ItemList {...defaultProps} items={createMockItems(50)} pageIndex={0} />);

      expect(screen.getByText('Page 1 of 2')).toBeInTheDocument();
    });

    it('should disable Previous button on first page', () => {
      render(<ItemList {...defaultProps} items={createMockItems(50)} pageIndex={0} />);

      expect(screen.getByText('Previous')).toBeDisabled();
    });

    it('should disable Next button on last page', () => {
      render(<ItemList {...defaultProps} items={createMockItems(50)} pageIndex={1} />);

      expect(screen.getByText('Next')).toBeDisabled();
    });

    it('should enable both buttons on middle page', () => {
      render(<ItemList {...defaultProps} items={createMockItems(75)} pageIndex={1} />);

      expect(screen.getByText('Previous')).not.toBeDisabled();
      expect(screen.getByText('Next')).not.toBeDisabled();
    });

    it('should call onPageChange when clicking Next', async () => {
      const user = userEvent.setup();
      const handlePageChange = vi.fn();

      render(
        <ItemList
          {...defaultProps}
          items={createMockItems(50)}
          pageIndex={0}
          onPageChange={handlePageChange}
        />
      );

      await user.click(screen.getByText('Next'));

      expect(handlePageChange).toHaveBeenCalledWith(1);
    });

    it('should call onPageChange when clicking Previous', async () => {
      const user = userEvent.setup();
      const handlePageChange = vi.fn();

      render(
        <ItemList
          {...defaultProps}
          items={createMockItems(50)}
          pageIndex={1}
          onPageChange={handlePageChange}
        />
      );

      await user.click(screen.getByText('Previous'));

      expect(handlePageChange).toHaveBeenCalledWith(0);
    });

    it('should show only items for current page', () => {
      render(<ItemList {...defaultProps} items={createMockItems(30)} pageIndex={1} />);

      // Page 2 should show items 26-30
      expect(screen.queryByText('Item 1')).not.toBeInTheDocument();
      expect(screen.queryByText('Item 25')).not.toBeInTheDocument();
      expect(screen.getByText('Item 26')).toBeInTheDocument();
      expect(screen.getByText('Item 30')).toBeInTheDocument();
    });

    it('should handle out of bounds page index', () => {
      render(<ItemList {...defaultProps} items={createMockItems(30)} pageIndex={10} />);

      // Should clamp to last page
      expect(screen.getByText('Page 2 of 2')).toBeInTheDocument();
      expect(screen.getByText('Item 26')).toBeInTheDocument();
    });

    it('should handle negative page index', () => {
      render(<ItemList {...defaultProps} items={createMockItems(30)} pageIndex={-5} />);

      // Should clamp to first page
      expect(screen.getByText('Page 1 of 2')).toBeInTheDocument();
      expect(screen.getByText('Item 1')).toBeInTheDocument();
    });
  });

  describe('visibility filter', () => {
    const createMixedItems = (): Item[] => [
      { id: 1, workspaceId: 1, collectionId: 1, categoryId: 1, templateKey: null, name: 'Public Item 1', summary: '', description: '', properties: [], images: [], visibility: Visibility.Public, effectiveIsPublic: true, userFlag: UserFlag.Have },
      { id: 2, workspaceId: 1, collectionId: 1, categoryId: 1, templateKey: null, name: 'Public Item 2', summary: '', description: '', properties: [], images: [], visibility: Visibility.Public, effectiveIsPublic: true, userFlag: UserFlag.Have },
      { id: 3, workspaceId: 1, collectionId: 1, categoryId: 1, templateKey: null, name: 'Private Item 1', summary: '', description: '', properties: [], images: [], visibility: Visibility.Private, effectiveIsPublic: false, userFlag: UserFlag.Have },
    ];

    it('should render VisibilityFilter', () => {
      render(<ItemList {...defaultProps} />);
      expect(screen.getByRole('group', { name: 'Visibility filter' })).toBeInTheDocument();
    });

    it('should show all items by default', () => {
      render(<ItemList {...defaultProps} items={createMixedItems()} />);
      expect(screen.getByText('Public Item 1')).toBeInTheDocument();
      expect(screen.getByText('Public Item 2')).toBeInTheDocument();
      expect(screen.getByText('Private Item 1')).toBeInTheDocument();
    });

    it('should filter to public items only when Public is selected', async () => {
      const user = userEvent.setup();
      render(<ItemList {...defaultProps} items={createMixedItems()} />);

      // Target the filter button specifically within the filter bar
      const filterBar = screen.getByRole('group', { name: 'Visibility filter' });
      const publicFilterBtn = filterBar.querySelector('.filter-btn:nth-child(2)') as HTMLElement;
      await user.click(publicFilterBtn);
      expect(screen.getByText('Public Item 1')).toBeInTheDocument();
      expect(screen.getByText('Public Item 2')).toBeInTheDocument();
      expect(screen.queryByText('Private Item 1')).not.toBeInTheDocument();
    });

    it('should filter to private items only when Private is selected', async () => {
      const user = userEvent.setup();
      render(<ItemList {...defaultProps} items={createMixedItems()} />);

      await user.click(screen.getByText('Private'));
      expect(screen.queryByText('Public Item 1')).not.toBeInTheDocument();
      expect(screen.queryByText('Public Item 2')).not.toBeInTheDocument();
      expect(screen.getByText('Private Item 1')).toBeInTheDocument();
    });

    it('should show correct filtered count', async () => {
      const user = userEvent.setup();
      render(<ItemList {...defaultProps} items={createMixedItems()} />);

      expect(screen.getByText('Showing 3 items')).toBeInTheDocument();

      const filterBar = screen.getByRole('group', { name: 'Visibility filter' });
      const publicFilterBtn = filterBar.querySelector('.filter-btn:nth-child(2)') as HTMLElement;
      await user.click(publicFilterBtn);
      expect(screen.getByText('Showing 2 items')).toBeInTheDocument();
    });

    it('should reset page to 0 when filter changes', async () => {
      const user = userEvent.setup();
      const handlePageChange = vi.fn();
      render(<ItemList {...defaultProps} items={createMixedItems()} onPageChange={handlePageChange} />);

      await user.click(screen.getByText('Private'));
      expect(handlePageChange).toHaveBeenCalledWith(0);
    });

    it('should show No items when filter matches nothing', async () => {
      const user = userEvent.setup();
      const allPrivateItems = createMockItems(3);
      render(<ItemList {...defaultProps} items={allPrivateItems} />);

      const filterBar = screen.getByRole('group', { name: 'Visibility filter' });
      const publicFilterBtn = filterBar.querySelector('.filter-btn:nth-child(2)') as HTMLElement;
      await user.click(publicFilterBtn);
      expect(screen.getByText('No items')).toBeInTheDocument();
    });
  });

  describe('selection mode and bulk actions', () => {
    beforeEach(() => {
      mockBulkPublishItems.mockReset();
      mockBulkUnpublishItems.mockReset();
      mockBulkPublishItems.mockResolvedValue({ publishedCount: 0, promoted: [], requiresSlugSetup: false });
      mockBulkUnpublishItems.mockResolvedValue({ unpublishedCount: 0 });
    });

    it('should show Select button', () => {
      render(<ItemList {...defaultProps} />);
      expect(screen.getByText('Select')).toBeInTheDocument();
    });

    it('should enter selection mode when clicking Select', async () => {
      const user = userEvent.setup();
      const { container } = render(<ItemList {...defaultProps} />);

      await user.click(screen.getByText('Select'));
      // Checkboxes should appear on cards
      expect(container.querySelectorAll('input[type="checkbox"]').length).toBe(3);
    });

    it('should show BulkActionBar when items are selected', async () => {
      const user = userEvent.setup();
      render(<ItemList {...defaultProps} />);

      await user.click(screen.getByText('Select'));
      // Click on first item card to select it
      await user.click(screen.getByRole('button', { name: 'Select Item 1' }));

      expect(screen.getByText('Publish Selected')).toBeInTheDocument();
      expect(screen.getByText('Make Private')).toBeInTheDocument();
    });

    it('should not show BulkActionBar when no items are selected', async () => {
      const user = userEvent.setup();
      render(<ItemList {...defaultProps} />);

      await user.click(screen.getByText('Select'));
      expect(screen.queryByText('Publish Selected')).not.toBeInTheDocument();
    });

    it('should call bulkPublishItems when clicking Publish Selected', async () => {
      const user = userEvent.setup();
      render(<ItemList {...defaultProps} />);

      await user.click(screen.getByText('Select'));
      await user.click(screen.getByRole('button', { name: 'Select Item 1' }));
      await user.click(screen.getByText('Publish Selected'));

      expect(mockBulkPublishItems).toHaveBeenCalledWith([1]);
    });

    it('should call bulkUnpublishItems when clicking Make Private', async () => {
      const user = userEvent.setup();
      render(<ItemList {...defaultProps} />);

      await user.click(screen.getByText('Select'));
      await user.click(screen.getByRole('button', { name: 'Select Item 2' }));
      await user.click(screen.getByText('Make Private'));

      expect(mockBulkUnpublishItems).toHaveBeenCalledWith([2]);
    });

    it('should exit selection mode when clicking Cancel in BulkActionBar', async () => {
      const user = userEvent.setup();
      const { container } = render(<ItemList {...defaultProps} />);

      await user.click(screen.getByText('Select'));
      await user.click(screen.getByRole('button', { name: 'Select Item 1' }));
      await user.click(screen.getAllByText('Cancel')[0]);

      expect(container.querySelectorAll('input[type="checkbox"]').length).toBe(0);
    });

    it('should toggle item selection on repeated clicks', async () => {
      const user = userEvent.setup();
      render(<ItemList {...defaultProps} />);

      await user.click(screen.getByText('Select'));

      // Select item 1
      await user.click(screen.getByRole('button', { name: 'Select Item 1' }));
      expect(screen.getByText('1')).toBeInTheDocument(); // count in bulk bar

      // Deselect item 1
      await user.click(screen.getByRole('button', { name: 'Select Item 1' }));
      // BulkActionBar should not render when 0 items selected
      expect(screen.queryByText('Publish Selected')).not.toBeInTheDocument();
    });

    it('should hide Select button when in selection mode', async () => {
      const user = userEvent.setup();
      render(<ItemList {...defaultProps} />);

      await user.click(screen.getByText('Select'));
      expect(screen.queryByText('Select')).not.toBeInTheDocument();
    });

    it('should clear selections after bulk publish', async () => {
      const user = userEvent.setup();
      const { container } = render(<ItemList {...defaultProps} />);

      await user.click(screen.getByText('Select'));
      await user.click(screen.getByRole('button', { name: 'Select Item 1' }));
      await user.click(screen.getByText('Publish Selected'));

      // After bulk publish, selection mode should exit
      expect(container.querySelectorAll('input[type="checkbox"]').length).toBe(0);
    });

    it('should clear selections after bulk unpublish', async () => {
      const user = userEvent.setup();
      const { container } = render(<ItemList {...defaultProps} />);

      await user.click(screen.getByText('Select'));
      await user.click(screen.getByRole('button', { name: 'Select Item 1' }));
      await user.click(screen.getByText('Make Private'));

      // After bulk unpublish, selection mode should exit
      expect(container.querySelectorAll('input[type="checkbox"]').length).toBe(0);
    });
  });
});
