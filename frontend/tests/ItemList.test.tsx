import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ItemList from '../src/components/item/ItemList';
import type { Item } from '../src/utils/types';

describe('ItemList', () => {
  const createMockItems = (count: number): Item[] => {
    return Array.from({ length: count }, (_, i) => ({
      id: i + 1,
      tenantId: 1,
      categoryId: 1,
      name: `Item ${i + 1}`,
      summary: `Summary ${i + 1}`,
      description: `Description ${i + 1}`,
      properties: [],
      images: [],
    }));
  };

  const defaultProps = {
    items: createMockItems(3),
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

      await user.click(screen.getByText('Item 2'));

      expect(handleSelect).toHaveBeenCalledWith(2);
    });

    it('should call onSelect when pressing Enter on an item', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();

      render(<ItemList {...defaultProps} onSelect={handleSelect} />);

      const row = screen.getByRole('button', { name: 'Select Item 1' });
      row.focus();
      await user.keyboard('{Enter}');

      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('should call onSelect when pressing Space on an item', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();

      render(<ItemList {...defaultProps} onSelect={handleSelect} />);

      const row = screen.getByRole('button', { name: 'Select Item 1' });
      row.focus();
      await user.keyboard(' ');

      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('should highlight selected item', () => {
      render(<ItemList {...defaultProps} selectedId={2} />);

      const rows = screen.getAllByRole('button');
      const selectedRow = rows.find(row => row.getAttribute('aria-label') === 'Select Item 2');

      expect(selectedRow).toHaveClass('list__tr--active');
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
        tenantId: 1,
        categoryId: 1,
        name: 'Item without summary',
        summary: '',
        description: 'Desc',
        properties: [],
        images: [],
      }];

      render(<ItemList {...defaultProps} items={items} />);

      expect(screen.getByText('Item without summary')).toBeInTheDocument();
    });

    it('should not call onSelect for item with null id', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();

      const itemsWithNullId: Item[] = [{
        id: null,
        tenantId: 1,
        categoryId: 1,
        name: 'Item with null id',
        summary: 'Summary',
        description: 'Desc',
        properties: [],
        images: [],
      }];

      render(<ItemList {...defaultProps} items={itemsWithNullId} onSelect={handleSelect} />);

      const row = screen.getByRole('button', { name: 'Select Item with null id' });
      await user.click(row);

      expect(handleSelect).not.toHaveBeenCalled();
    });

    it('should not call onSelect when pressing Enter on item with null id', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();

      const itemsWithNullId: Item[] = [{
        id: null,
        tenantId: 1,
        categoryId: 1,
        name: 'Item with null id',
        summary: 'Summary',
        description: 'Desc',
        properties: [],
        images: [],
      }];

      render(<ItemList {...defaultProps} items={itemsWithNullId} onSelect={handleSelect} />);

      const row = screen.getByRole('button', { name: 'Select Item with null id' });
      row.focus();
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
});

