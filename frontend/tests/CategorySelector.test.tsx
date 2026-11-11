import { expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CategorySelector from '../src/components/category/CategorySelector';
import { createMockCategory as category } from './testUtils';

it('associates each instance with its own label and handles category and null selection', async () => {
  const first = vi.fn(), second = vi.fn();
  const categories = [category({ categoryId: 1, name: 'Books' }), category({ categoryId: 2, name: 'Fiction', parentCategoryId: 1 })];
  render(<>
    <CategorySelector categories={categories} selectedCategoryId={null} onChange={first} />
    <CategorySelector categories={categories} selectedCategoryId={2} onChange={second} label="Parent Category" nullLabel="Root level" variant="modal" />
  </>);
  const itemSelect = screen.getByRole('combobox', { name: 'Category' });
  const parentSelect = screen.getByRole('combobox', { name: 'Parent Category' });
  expect(itemSelect.id).not.toBe(parentSelect.id);
  expect(itemSelect).toHaveValue('');
  expect(parentSelect).toHaveValue('2');
  await userEvent.selectOptions(itemSelect, '2');
  expect(first).toHaveBeenCalledExactlyOnceWith(2);
  await userEvent.selectOptions(parentSelect, '');
  expect(second).toHaveBeenCalledExactlyOnceWith(null);
  expect(within(parentSelect).getByRole('option', { name: 'Root level' })).toBeInTheDocument();
});

it('uses the shared hierarchy for cycles, orphans and deep options with bounded indentation', () => {
  const categories = [category({ categoryId: 1, name: 'A', parentCategoryId: 2 }), category({ categoryId: 2, name: 'B', parentCategoryId: 1 }),
    category({ categoryId: 3, name: 'Orphan', parentCategoryId: 99 }),
    ...Array.from({ length: 7 }, (_, index) => category({ categoryId: index + 10, parentCategoryId: index === 0 ? null : index + 9, name: `Level ${index}` }))];
  render(<CategorySelector categories={categories} selectedCategoryId={1} onChange={vi.fn()} allowNull={false} />);
  expect(screen.getAllByRole('option')).toHaveLength(11);
  expect(screen.queryByRole('option', { name: 'No category' })).not.toBeInTheDocument();
  expect(screen.getByRole('option', { name: 'Orphan' })).toHaveValue('3');
  expect(screen.getByRole('option', { name: '└ B' })).toHaveValue('2');
  expect(screen.getByRole('option', { name: '└ Level 6' }).textContent).toBe('          └ Level 6');
});

it('shows unavailable selections explicitly and never silently replaces them', async () => {
  const onChange = vi.fn();
  const { rerender } = render(<CategorySelector categories={[]} selectedCategoryId={99} onChange={onChange} />);
  expect(screen.getByRole('combobox')).toHaveValue('99');
  expect(screen.getByRole('combobox')).toHaveAttribute('aria-invalid', 'true');
  expect(screen.getByRole('option', { name: 'Unavailable category (99)' })).toBeDisabled();
  expect(onChange).not.toHaveBeenCalled();
  await userEvent.selectOptions(screen.getByRole('combobox'), '');
  expect(onChange).toHaveBeenCalledWith(null);
  rerender(<CategorySelector categories={[]} selectedCategoryId={null} onChange={onChange} allowNull={false} />);
  expect(screen.getByRole('combobox')).toHaveValue('');
  expect(screen.getByRole('option', { name: 'Select a category' })).toBeDisabled();
});
