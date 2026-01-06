import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ItemDetail from '../src/ItemDetail';
import type { Item } from '../src/types';

describe('ItemDetail', () => {
  const mockItem: Item = {
    id: 1,
    tenantId: 1,
    categoryId: 2,
    name: 'Test Item',
    summary: 'Test summary',
    description: 'Test description',
    properties: [
      { category: 'General', name: 'Prop1', value: 'Value1' },
      { category: 'General', name: 'Prop2', value: 'Value2' },
      { category: 'Technical', name: 'Prop3', value: 'Value3' },
    ],
    images: [
      { url: 'https://example.com/image1.jpg', alt: 'Image 1' },
      { url: 'https://example.com/image2.jpg', alt: 'Image 2' },
    ],
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('snapshots', () => {
    it('should render empty state', () => {
      const { container } = render(<ItemDetail item={null} />);
      expect(container).toMatchSnapshot();
    });

    it('should render view mode', () => {
      const { container } = render(<ItemDetail item={mockItem} onEdit={() => {}} />);
      expect(container).toMatchSnapshot();
    });

    it('should render item without properties', () => {
      const itemWithoutProps = { ...mockItem, properties: [] };
      const { container } = render(<ItemDetail item={itemWithoutProps} />);
      expect(container).toMatchSnapshot();
    });

    it('should render item without images', () => {
      const itemWithoutImages = { ...mockItem, images: [] };
      const { container } = render(<ItemDetail item={itemWithoutImages} />);
      expect(container).toMatchSnapshot();
    });
  });

  describe('view mode', () => {
    it('should show placeholder when no item selected', () => {
      render(<ItemDetail item={null} />);

      expect(screen.getByText('Select an item')).toBeInTheDocument();
    });

    it('should display item name', () => {
      render(<ItemDetail item={mockItem} />);

      expect(screen.getByText('Test Item')).toBeInTheDocument();
    });

    it('should display item description', () => {
      render(<ItemDetail item={mockItem} />);

      expect(screen.getByText('Test description')).toBeInTheDocument();
    });

    it('should display properties grouped by category', () => {
      render(<ItemDetail item={mockItem} />);

      expect(screen.getByText('General')).toBeInTheDocument();
      expect(screen.getByText('Technical')).toBeInTheDocument();
      expect(screen.getByText('Prop1')).toBeInTheDocument();
      expect(screen.getByText('Value1')).toBeInTheDocument();
    });

    it('should group properties without category under Other', () => {
      const itemWithUncategorizedProps: Item = {
        ...mockItem,
        properties: [
          { category: '', name: 'Uncategorized', value: 'Value' },
          { category: '   ', name: 'Whitespace', value: 'Value2' },
        ],
      };

      render(<ItemDetail item={itemWithUncategorizedProps} />);

      expect(screen.getByText('Other')).toBeInTheDocument();
      expect(screen.getByText('Uncategorized')).toBeInTheDocument();
    });

    it('should show edit button when onEdit is provided', () => {
      render(<ItemDetail item={mockItem} onEdit={() => {}} />);

      expect(screen.getByText('Edit')).toBeInTheDocument();
    });

    it('should not show edit button when onEdit is not provided', () => {
      render(<ItemDetail item={mockItem} />);

      expect(screen.queryByText('Edit')).not.toBeInTheDocument();
    });

    it('should show back button when onClose is provided', () => {
      render(<ItemDetail item={mockItem} onClose={() => {}} />);

      expect(screen.getByText('Back to list')).toBeInTheDocument();
    });

    it('should call onClose when clicking back button', async () => {
      const user = userEvent.setup();
      const handleClose = vi.fn();

      render(<ItemDetail item={mockItem} onClose={handleClose} />);

      await user.click(screen.getByText('Back to list'));

      expect(handleClose).toHaveBeenCalled();
    });

    it('should call onEdit when clicking edit button', async () => {
      const user = userEvent.setup();
      const handleEdit = vi.fn();

      render(<ItemDetail item={mockItem} onEdit={handleEdit} />);

      await user.click(screen.getByText('Edit'));

      expect(handleEdit).toHaveBeenCalled();
    });
  });
});
