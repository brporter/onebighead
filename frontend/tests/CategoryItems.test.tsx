import { expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ComponentProps } from 'react';
import type ItemList from '../src/components/item/ItemList';
import { createMockCategory, createMockItem } from './testUtils';
import { CategoryItems } from '../src/components/category/CategoryItems';

vi.mock('../src/components/item/ItemList', () => ({ default: ({ items, pageIndex, onPageChange, onSelect, onAddItem }: ComponentProps<typeof ItemList>) => <>
  <p>Page index: {pageIndex}</p>
  <button onClick={() => onPageChange(pageIndex + 1)}>Next page</button>
  <button onClick={() => onSelect(1)}>Select first</button>
  <button onClick={onAddItem ?? undefined}>Add item</button>
  <ul>{items.map(item => <li key={item.id}>{item.name}</li>)}</ul>
</> }));

const categories = [
  createMockCategory({ categoryId: 1, parentCategoryId: null, name: 'Books' }),
  createMockCategory({ categoryId: 2, parentCategoryId: 1, name: 'Fiction' }),
  createMockCategory({ categoryId: 3, parentCategoryId: 2, name: 'Mystery' }),
  createMockCategory({ categoryId: 4, parentCategoryId: null, name: 'Music' }),
];
const items = [
  createMockItem({ id: 1, categoryId: 1, name: 'A book' }),
  createMockItem({ id: 2, categoryId: 2, name: 'A novel' }),
  createMockItem({ id: 3, categoryId: 3, name: 'A mystery' }),
  createMockItem({ id: 4, categoryId: 4, name: 'A record' }),
  createMockItem({ id: 5, categoryId: null, name: 'Uncategorized' }),
];
const props = () => ({ categoryId: 1, categories, items, loading: false, error: null, onRetry: vi.fn(), onSelect: vi.fn(), onAdd: vi.fn() });

it('filters descendants and resets pagination when the filter changes', async () => {
  render(<CategoryItems {...props()} />);
  expect(screen.getAllByRole('listitem')).toHaveLength(3);
  expect(screen.queryByText('A record')).not.toBeInTheDocument();
  expect(screen.queryByText('Uncategorized')).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Next page' }));
  expect(screen.getByText('Page index: 1')).toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText('Filter by subcategory:'), '2');
  expect(screen.getAllByRole('listitem')).toHaveLength(2);
  expect(screen.getByText('Page index: 0')).toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText('Filter by subcategory:'), '');
  expect(screen.getAllByRole('listitem')).toHaveLength(3);
});

it('delegates selection, creation and retry without owning data requests', async () => {
  const p = props();
  const { rerender } = render(<CategoryItems {...p} />);
  await userEvent.click(screen.getByRole('button', { name: 'Select first' }));
  await userEvent.click(screen.getByRole('button', { name: 'Add item' }));
  expect(p.onSelect).toHaveBeenCalledWith(1);
  expect(p.onAdd).toHaveBeenCalledOnce();
  rerender(<CategoryItems {...p} error="Unavailable" />);
  expect(screen.getByRole('alert')).toHaveTextContent('Unavailable');
  await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
  expect(p.onRetry).toHaveBeenCalledOnce();
});

it('keeps cached content visible while refreshing and shows initial loading', () => {
  const { rerender } = render(<CategoryItems {...props()} loading />);
  expect(screen.getByRole('region', { name: 'Category items' })).toHaveAttribute('aria-busy', 'true');
  expect(screen.getAllByRole('listitem')).toHaveLength(3);
  rerender(<CategoryItems {...props()} loading items={[]} />);
  expect(screen.getByRole('status')).toHaveTextContent('Loading items');
});

it('keeps filters within the collection and recovers when a selected subcategory is removed', async () => {
  const scoped = [...categories, createMockCategory({ categoryId: 10, parentCategoryId: 1, collectionId: 2, name: 'Foreign category' })];
  const mixed = [...items, createMockItem({ id: 10, categoryId: 1, collectionId: 2, name: 'Foreign collection item' }),
    createMockItem({ id: 11, categoryId: 1, workspaceId: 2, name: 'Foreign workspace item' })];
  const p = { ...props(), categories: scoped, items: mixed };
  const { rerender } = render(<CategoryItems {...p} />);
  expect(screen.queryByText('Foreign category')).not.toBeInTheDocument();
  expect(screen.queryByText('Foreign collection item')).not.toBeInTheDocument();
  expect(screen.queryByText('Foreign workspace item')).not.toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText('Filter by subcategory:'), '2');
  rerender(<CategoryItems {...p} categories={scoped.filter(value => value.categoryId !== 2)} />);
  expect(screen.getByText('A book')).toBeInTheDocument();
  expect(screen.queryByText('A novel')).not.toBeInTheDocument();
  expect(screen.queryByText('A mystery')).not.toBeInTheDocument();
  rerender(<CategoryItems {...p} categoryId={999} />);
  expect(screen.queryAllByRole('listitem')).toHaveLength(0);
});
