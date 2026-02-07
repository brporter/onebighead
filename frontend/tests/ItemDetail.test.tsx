import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ItemDetail from '../src/components/item/ItemDetail';
import type { Item } from '../src/utils/types';
import { UserFlag, Visibility } from '../src/utils/types';

describe('ItemDetail', () => {
  const mockItem: Item = {
    id: 1,
    workspaceId: 1,
    collectionId: 1,
    categoryId: 2,
    templateKey: null,
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
    visibility: Visibility.Default,
    effectiveIsPublic: true,
    userFlag: UserFlag.None,
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

  describe('user flag ribbon', () => {
    it('should not show ribbon for None flag', () => {
      render(<ItemDetail item={{ ...mockItem, userFlag: UserFlag.None }} />);
      expect(screen.queryByText('I Want This!')).not.toBeInTheDocument();
      expect(screen.queryByText('For Trade/Sale')).not.toBeInTheDocument();
    });

    it('should not show ribbon for Have flag', () => {
      render(<ItemDetail item={{ ...mockItem, userFlag: UserFlag.Have }} />);
      expect(screen.queryByText('I Want This!')).not.toBeInTheDocument();
      expect(screen.queryByText('For Trade/Sale')).not.toBeInTheDocument();
    });

    it('should show Want ribbon', () => {
      render(<ItemDetail item={{ ...mockItem, userFlag: UserFlag.Want }} />);
      expect(screen.getByText('I Want This!')).toBeInTheDocument();
    });

    it('should show Trade/Sell ribbon', () => {
      render(<ItemDetail item={{ ...mockItem, userFlag: UserFlag.TradeOrSell }} />);
      expect(screen.getByText('For Trade/Sale')).toBeInTheDocument();
    });

    it('should render snapshot with None flag (no ribbon)', () => {
      const { container } = render(
        <ItemDetail item={{ ...mockItem, userFlag: UserFlag.None }} onEdit={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });

    it('should render snapshot with Have flag (no ribbon)', () => {
      const { container } = render(
        <ItemDetail item={{ ...mockItem, userFlag: UserFlag.Have }} onEdit={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });

    it('should render snapshot with Want flag (with ribbon)', () => {
      const { container } = render(
        <ItemDetail item={{ ...mockItem, userFlag: UserFlag.Want }} onEdit={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });

    it('should render snapshot with TradeOrSell flag (with ribbon)', () => {
      const { container } = render(
        <ItemDetail item={{ ...mockItem, userFlag: UserFlag.TradeOrSell }} onEdit={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });
  });
});
