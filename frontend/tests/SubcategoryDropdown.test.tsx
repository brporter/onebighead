import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SubcategoryDropdown from '../src/SubcategoryDropdown';
import type { Category } from '../src/types';

describe('SubcategoryDropdown', () => {
  const mockSubcategories: Category[] = [
    { tenantId: 1, categoryId: 1, name: 'Subcategory 1', description: 'Desc 1', parentCategoryId: null, isSystem: false },
    { tenantId: 1, categoryId: 2, name: 'Subcategory 2', description: 'Desc 2', parentCategoryId: null, isSystem: false },
    { tenantId: 1, categoryId: 3, name: 'Subcategory 3', description: 'Desc 3', parentCategoryId: null, isSystem: false },
  ];

  describe('snapshots', () => {
    it('should render nothing when subcategories is empty', () => {
      const { container } = render(
        <SubcategoryDropdown subcategories={[]} selectedId={null} onChange={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });

    it('should render nothing when subcategories is undefined', () => {
      const { container } = render(
        <SubcategoryDropdown selectedId={null} onChange={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });

    it('should render dropdown with subcategories', () => {
      const { container } = render(
        <SubcategoryDropdown
          subcategories={mockSubcategories}
          selectedId={null}
          onChange={() => {}}
        />
      );
      expect(container).toMatchSnapshot();
    });

    it('should render with selected subcategory', () => {
      const { container } = render(
        <SubcategoryDropdown
          subcategories={mockSubcategories}
          selectedId={2}
          onChange={() => {}}
        />
      );
      expect(container).toMatchSnapshot();
    });
  });

  describe('functionality', () => {
    it('should return null when no subcategories', () => {
      const { container } = render(
        <SubcategoryDropdown subcategories={[]} selectedId={null} onChange={() => {}} />
      );
      expect(container.firstChild).toBeNull();
    });

    it('should render all options including "All items"', () => {
      render(
        <SubcategoryDropdown
          subcategories={mockSubcategories}
          selectedId={null}
          onChange={() => {}}
        />
      );

      expect(screen.getByRole('combobox')).toBeInTheDocument();
      expect(screen.getByText('All items')).toBeInTheDocument();
      expect(screen.getByText('Subcategory 1')).toBeInTheDocument();
      expect(screen.getByText('Subcategory 2')).toBeInTheDocument();
      expect(screen.getByText('Subcategory 3')).toBeInTheDocument();
    });

    it('should call onChange with category id when selecting a subcategory', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      render(
        <SubcategoryDropdown
          subcategories={mockSubcategories}
          selectedId={null}
          onChange={handleChange}
        />
      );

      await user.selectOptions(screen.getByRole('combobox'), '2');

      expect(handleChange).toHaveBeenCalledWith(2);
    });

    it('should call onChange with null when selecting "All items"', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      render(
        <SubcategoryDropdown
          subcategories={mockSubcategories}
          selectedId={2}
          onChange={handleChange}
        />
      );

      await user.selectOptions(screen.getByRole('combobox'), '');

      expect(handleChange).toHaveBeenCalledWith(null);
    });

    it('should display selected value correctly', () => {
      render(
        <SubcategoryDropdown
          subcategories={mockSubcategories}
          selectedId={2}
          onChange={() => {}}
        />
      );

      expect(screen.getByRole('combobox')).toHaveValue('2');
    });

    it('should have proper label', () => {
      render(
        <SubcategoryDropdown
          subcategories={mockSubcategories}
          selectedId={null}
          onChange={() => {}}
        />
      );

      expect(screen.getByLabelText('Filter by subcategory:')).toBeInTheDocument();
    });
  });
});

