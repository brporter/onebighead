import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ItemCard from '../src/components/item/ItemCard';
import type { Item } from '../src/utils/types';
import { Visibility, UserFlag } from '../src/utils/types';
import type { AccentColor } from '../src/utils/accentColors';

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
