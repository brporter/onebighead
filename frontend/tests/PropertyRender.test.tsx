import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import PropertyRender from '../src/PropertyRender';
import type { ItemProperty } from '../src/types';

describe('PropertyRender', () => {
  const mockProperties: ItemProperty[] = [
    { category: 'General', name: 'Prop1', value: 'Value1' },
    { category: 'General', name: 'Prop2', value: 'Value2' },
    { category: 'Technical', name: 'Prop3', value: 'Value3' },
  ];

  describe('snapshots', () => {
    it('should render with properties', () => {
      const { container } = render(<PropertyRender properties={mockProperties} />);
      expect(container).toMatchSnapshot();
    });

    it('should render with empty properties', () => {
      const { container } = render(<PropertyRender properties={[]} />);
      expect(container).toMatchSnapshot();
    });

    it('should render with undefined properties', () => {
      const { container } = render(<PropertyRender />);
      expect(container).toMatchSnapshot();
    });
  });

  describe('display', () => {
    it('should display properties grouped by category', () => {
      render(<PropertyRender properties={mockProperties} />);

      expect(screen.getByText('General')).toBeInTheDocument();
      expect(screen.getByText('Technical')).toBeInTheDocument();
    });

    it('should display property names and values', () => {
      render(<PropertyRender properties={mockProperties} />);

      expect(screen.getByText('Prop1')).toBeInTheDocument();
      expect(screen.getByText('Value1')).toBeInTheDocument();
      expect(screen.getByText('Prop3')).toBeInTheDocument();
      expect(screen.getByText('Value3')).toBeInTheDocument();
    });

    it('should group properties without category under Other', () => {
      const propsWithoutCategory: ItemProperty[] = [
        { category: '', name: 'Uncategorized', value: 'Value' },
        { category: '   ', name: 'Whitespace', value: 'Value2' },
      ];

      render(<PropertyRender properties={propsWithoutCategory} />);

      expect(screen.getByText('Other')).toBeInTheDocument();
      expect(screen.getByText('Uncategorized')).toBeInTheDocument();
      expect(screen.getByText('Whitespace')).toBeInTheDocument();
    });

    it('should render nothing when properties array is empty', () => {
      const { container } = render(<PropertyRender properties={[]} />);

      expect(container.querySelector('.detail__properties')).not.toBeInTheDocument();
    });

    it('should render nothing when properties is undefined', () => {
      const { container } = render(<PropertyRender />);

      expect(container.querySelector('.detail__properties')).not.toBeInTheDocument();
    });
  });
});

