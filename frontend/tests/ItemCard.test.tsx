import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ItemCard from '../src/components/item/ItemCard';
import type { Item } from '../src/utils/types';
import { Visibility, UserFlag } from '../src/utils/types';
import type { AccentColor } from '../src/utils/accentColors';

const mockPublishItem = vi.fn();
const mockUnpublishItem = vi.fn();

vi.mock('../src/contexts/useData', () => ({
  useData: () => ({
    publishItem: mockPublishItem,
    unpublishItem: mockUnpublishItem,
  }),
}));

describe('ItemCard', () => {
  const defaultAccent: AccentColor = { start: '#c77d4a', end: '#d4a574', name: 'Warm copper' };

  const itemWithImages: Item = {
    id: 1,
    workspaceId: 1,
    collectionId: 1,
    categoryId: 1,
    templateKey: null,
    name: 'Leica M3',
    summary: 'Classic rangefinder',
    description: 'A pristine example',
    properties: [
      { category: 'Details', name: 'Year', value: '1956' },
      { category: 'Details', name: 'Condition', value: 'Excellent' },
    ],
    images: [{ url: '/images/leica.jpg', alt: 'Leica M3' }],
    visibility: Visibility.Private,
    effectiveIsPublic: false,
    userFlag: UserFlag.Have,
  };

  const itemWithoutImages: Item = {
    id: 2,
    workspaceId: 1,
    collectionId: 1,
    categoryId: 1,
    templateKey: null,
    name: 'Nikon FM2',
    summary: 'Mechanical workhorse',
    description: 'Titanium shutter',
    properties: [
      { category: 'Details', name: 'Year', value: '1982' },
    ],
    images: [],
    visibility: Visibility.Private,
    effectiveIsPublic: false,
    userFlag: UserFlag.Have,
  };

  const defaultProps = {
    item: itemWithImages,
    accentColor: defaultAccent,
    isSelected: false,
    onSelect: vi.fn(),
  };

  describe('snapshots', () => {
    it('should render image card', () => {
      const { container } = render(<ItemCard {...defaultProps} />);
      expect(container).toMatchSnapshot();
    });

    it('should render text-only card', () => {
      const { container } = render(<ItemCard {...defaultProps} item={itemWithoutImages} />);
      expect(container).toMatchSnapshot();
    });

    it('should render selected card', () => {
      const { container } = render(<ItemCard {...defaultProps} isSelected={true} />);
      expect(container).toMatchSnapshot();
    });
  });

  describe('image card rendering', () => {
    it('should render item name', () => {
      render(<ItemCard {...defaultProps} />);
      expect(screen.getByText('Leica M3')).toBeInTheDocument();
    });

    it('should render item summary as metadata', () => {
      render(<ItemCard {...defaultProps} />);
      expect(screen.getByText('Classic rangefinder')).toBeInTheDocument();
    });

    it('should render item image', () => {
      render(<ItemCard {...defaultProps} />);
      const img = screen.getByAltText('Leica M3');
      expect(img).toBeInTheDocument();
      expect(img).toHaveAttribute('src', '/images/leica.jpg');
    });

    it('should render accent ribbon with gradient', () => {
      const { container } = render(<ItemCard {...defaultProps} />);
      const ribbon = container.querySelector('.item-card__ribbon');
      expect(ribbon).toBeInTheDocument();
      expect(ribbon).toHaveStyle({ background: 'linear-gradient(90deg, #c77d4a, #d4a574)' });
    });
  });

  describe('text-only card rendering', () => {
    it('should have text-only modifier class when no images', () => {
      const { container } = render(<ItemCard {...defaultProps} item={itemWithoutImages} />);
      expect(container.querySelector('.item-card--textonly')).toBeInTheDocument();
    });

    it('should not have text-only modifier when images exist', () => {
      const { container } = render(<ItemCard {...defaultProps} />);
      expect(container.querySelector('.item-card--textonly')).not.toBeInTheDocument();
    });

    it('should render summary text on text-only cards', () => {
      render(<ItemCard {...defaultProps} item={itemWithoutImages} />);
      expect(screen.getByText('Mechanical workhorse')).toBeInTheDocument();
    });

    it('should render property pills on text-only cards', () => {
      render(<ItemCard {...defaultProps} item={itemWithoutImages} />);
      expect(screen.getByText('1982')).toBeInTheDocument();
    });
  });

  describe('interaction', () => {
    it('should call onSelect when clicked', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(<ItemCard {...defaultProps} onSelect={handleSelect} />);

      await user.click(screen.getByRole('button', { name: /Leica M3/ }));
      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('should call onSelect on Enter key', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(<ItemCard {...defaultProps} onSelect={handleSelect} />);

      const card = screen.getByRole('button', { name: /Leica M3/ });
      card.focus();
      await user.keyboard('{Enter}');
      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('should call onSelect on Space key', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(<ItemCard {...defaultProps} onSelect={handleSelect} />);

      const card = screen.getByRole('button', { name: /Leica M3/ });
      card.focus();
      await user.keyboard(' ');
      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('should not call onSelect for item with null id', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      const nullIdItem = { ...itemWithImages, id: null, name: 'Null item' };
      render(<ItemCard {...defaultProps} item={nullIdItem} onSelect={handleSelect} />);

      await user.click(screen.getByRole('button', { name: /Null item/ }));
      expect(handleSelect).not.toHaveBeenCalled();
    });

    it('should have selected class when isSelected is true', () => {
      const { container } = render(<ItemCard {...defaultProps} isSelected={true} />);
      expect(container.querySelector('.item-card--selected')).toBeInTheDocument();
    });
  });

  describe('publish/unpublish integration', () => {
    const publicItem: Item = {
      ...itemWithImages,
      effectiveIsPublic: true,
    };

    const privateItem: Item = {
      ...itemWithImages,
      effectiveIsPublic: false,
    };

    beforeEach(() => {
      mockPublishItem.mockReset();
      mockUnpublishItem.mockReset();
      mockPublishItem.mockResolvedValue({ published: { type: 'Item', id: 1, name: 'Leica M3' }, promoted: [], childrenPublished: 0, requiresSlugSetup: false });
      mockUnpublishItem.mockResolvedValue({ unpublished: { type: 'Item', id: 1, name: 'Leica M3' }, affectedPublicItems: 0, affectedPublicCategories: 0 });
    });

    it('should show PublicBadge when effectiveIsPublic is true', () => {
      render(<ItemCard {...defaultProps} item={publicItem} />);
      expect(screen.getByText('Public')).toBeInTheDocument();
    });

    it('should show PublishButton when item is private', () => {
      render(<ItemCard {...defaultProps} item={privateItem} />);
      expect(screen.getByText('Publish')).toBeInTheDocument();
    });

    it('should not show PublishButton when item is public', () => {
      render(<ItemCard {...defaultProps} item={publicItem} />);
      expect(screen.queryByText('Publish')).not.toBeInTheDocument();
    });

    it('should not show PublicBadge when item is private', () => {
      render(<ItemCard {...defaultProps} item={privateItem} />);
      expect(screen.queryByText('Public')).not.toBeInTheDocument();
    });

    it('should call publishItem when clicking Publish button', async () => {
      const user = userEvent.setup();
      render(<ItemCard {...defaultProps} item={privateItem} />);

      await user.click(screen.getByText('Publish'));
      expect(mockPublishItem).toHaveBeenCalledWith(1);
    });

    it('should call unpublishItem when clicking Unpublish on PublicBadge', async () => {
      const user = userEvent.setup();
      render(<ItemCard {...defaultProps} item={publicItem} />);

      // PublicBadge is a button, click it
      await user.click(screen.getByText('Public'));
      expect(mockUnpublishItem).toHaveBeenCalledWith(1);
    });

    it('should show SlugSetupModal when publish requires slug setup', async () => {
      mockPublishItem.mockResolvedValue({ published: { type: 'Item', id: 1, name: 'Leica M3' }, promoted: [], childrenPublished: 0, requiresSlugSetup: true });
      const user = userEvent.setup();
      render(<ItemCard {...defaultProps} item={privateItem} />);

      await user.click(screen.getByText('Publish'));
      expect(screen.getByText('Set Up Your Public Gallery')).toBeInTheDocument();
    });

    it('should retry publish after slug setup', async () => {
      mockPublishItem.mockResolvedValueOnce({ published: { type: 'Item', id: 1, name: 'Leica M3' }, promoted: [], childrenPublished: 0, requiresSlugSetup: true });
      mockPublishItem.mockResolvedValueOnce({ published: { type: 'Item', id: 1, name: 'Leica M3' }, promoted: [], childrenPublished: 0, requiresSlugSetup: false });
      const user = userEvent.setup();
      render(<ItemCard {...defaultProps} item={privateItem} />);

      await user.click(screen.getByText('Publish'));
      expect(screen.getByText('Set Up Your Public Gallery')).toBeInTheDocument();

      // Fill in slug and confirm
      await user.type(screen.getByLabelText('Gallery URL'), 'my-gallery');
      await user.click(screen.getByText('Create Gallery & Publish'));

      expect(mockPublishItem).toHaveBeenCalledTimes(2);
    });

    it('should close SlugSetupModal on cancel', async () => {
      mockPublishItem.mockResolvedValue({ published: { type: 'Item', id: 1, name: 'Leica M3' }, promoted: [], childrenPublished: 0, requiresSlugSetup: true });
      const user = userEvent.setup();
      render(<ItemCard {...defaultProps} item={privateItem} />);

      await user.click(screen.getByText('Publish'));
      expect(screen.getByText('Set Up Your Public Gallery')).toBeInTheDocument();

      await user.click(screen.getByText('Cancel'));
      expect(screen.queryByText('Set Up Your Public Gallery')).not.toBeInTheDocument();
    });

    it('should not call publishItem when item has null id', async () => {
      const user = userEvent.setup();
      const nullIdItem = { ...privateItem, id: null, name: 'No ID item' };
      render(<ItemCard {...defaultProps} item={nullIdItem} />);

      await user.click(screen.getByText('Publish'));
      expect(mockPublishItem).not.toHaveBeenCalled();
    });

    it('should not call unpublishItem when item has null id', async () => {
      const user = userEvent.setup();
      const nullIdItem = { ...publicItem, id: null, name: 'No ID item' };
      render(<ItemCard {...defaultProps} item={nullIdItem} />);

      await user.click(screen.getByText('Public'));
      expect(mockUnpublishItem).not.toHaveBeenCalled();
    });
  });

  describe('selection mode', () => {
    it('should show checkbox in selection mode', () => {
      const { container } = render(
        <ItemCard {...defaultProps} selectionMode={true} isChecked={false} onToggleCheck={vi.fn()} />
      );
      expect(container.querySelector('input[type="checkbox"]')).toBeInTheDocument();
    });

    it('should not show checkbox when not in selection mode', () => {
      const { container } = render(<ItemCard {...defaultProps} />);
      expect(container.querySelector('input[type="checkbox"]')).not.toBeInTheDocument();
    });

    it('should call onToggleCheck instead of onSelect in selection mode', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      const handleToggleCheck = vi.fn();
      render(
        <ItemCard {...defaultProps} onSelect={handleSelect} selectionMode={true} isChecked={false} onToggleCheck={handleToggleCheck} />
      );

      await user.click(screen.getByRole('button', { name: /Leica M3/ }));
      expect(handleToggleCheck).toHaveBeenCalledWith(1);
      expect(handleSelect).not.toHaveBeenCalled();
    });

    it('should reflect checked state', () => {
      const { container } = render(
        <ItemCard {...defaultProps} selectionMode={true} isChecked={true} onToggleCheck={vi.fn()} />
      );
      const checkbox = container.querySelector('input[type="checkbox"]') as HTMLInputElement;
      expect(checkbox.checked).toBe(true);
    });

    it('should add selectable class in selection mode', () => {
      const { container } = render(
        <ItemCard {...defaultProps} selectionMode={true} isChecked={false} onToggleCheck={vi.fn()} />
      );
      expect(container.querySelector('.item-card--selectable')).toBeInTheDocument();
    });

    it('should call onToggleCheck on Enter key in selection mode', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      const handleToggleCheck = vi.fn();
      render(
        <ItemCard {...defaultProps} onSelect={handleSelect} selectionMode={true} isChecked={false} onToggleCheck={handleToggleCheck} />
      );

      const card = screen.getByRole('button', { name: /Leica M3/ });
      card.focus();
      await user.keyboard('{Enter}');
      expect(handleToggleCheck).toHaveBeenCalledWith(1);
      expect(handleSelect).not.toHaveBeenCalled();
    });
  });

  describe('property pills', () => {
    it('should show max 3 property pills then overflow count on text-only cards', () => {
      const manyProps: Item = {
        ...itemWithoutImages,
        properties: [
          { category: 'A', name: 'P1', value: 'V1' },
          { category: 'A', name: 'P2', value: 'V2' },
          { category: 'A', name: 'P3', value: 'V3' },
          { category: 'A', name: 'P4', value: 'V4' },
          { category: 'A', name: 'P5', value: 'V5' },
          { category: 'A', name: 'P6', value: 'V6' },
        ],
      };
      render(<ItemCard {...defaultProps} item={manyProps} />);
      expect(screen.getByText('+3 more')).toBeInTheDocument();
    });

    it('should not show pills section on image cards', () => {
      const { container } = render(<ItemCard {...defaultProps} />);
      expect(container.querySelector('.item-card__props')).not.toBeInTheDocument();
    });
  });
});
