import { render, screen, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import ThemePreview from '../src/components/collection/ThemePreview';
import { createMockCollectionTheme as theme, createMockThemeCategory as category, createMockThemeTemplate as template } from './testUtils/factories';

it('shows template details and bounded category indentation with explicit parent labels', () => {
  const categories = Array.from({ length: 8 }, (_, i) => category({ name: `Category ${i}`, parentName: i ? `Category ${i - 1}` : null, description: i ? '' : 'Root description' }));
  render(<ThemePreview theme={theme({ categories: [...categories].reverse(), templates: [
    template({ name: 'Book', description: 'Track an edition', properties: [{ category: 'Edition', name: 'Publisher' }, { category: '', name: 'Notes' }] }),
    template({ itemTemplateId: 2, name: 'Blank', description: '' }),
  ] })} />);
  const templates = screen.getByRole('region', { name: 'Templates 2' });
  expect(within(templates).getByRole('heading', { name: 'Book' })).toBeInTheDocument();
  expect(within(templates).getByText('Track an edition')).toBeInTheDocument();
  expect(within(templates).getByText('No preset properties')).toBeInTheDocument();
  expect(within(screen.getByRole('list', { name: 'Book properties' })).getAllByRole('listitem').map(row => row.textContent)).toEqual(['Edition: Publisher', 'Notes']);
  const rows = within(screen.getByRole('region', { name: 'Categories 8' })).getAllByRole('listitem');
  expect(rows.map(row => row.querySelector('.themePreview__categoryName')?.textContent)).toEqual(categories.map(row => row.name));
  rows.forEach((row, i) => expect(row.style.getPropertyValue('--theme-depth')).toBe(String(Math.min(i, 4))));
  expect(within(rows[0]).getByText('Root description')).toBeInTheDocument();
  expect(within(rows[7]).getByText('Parent: Category 6')).toBeInTheDocument();
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
});

it('shows empty states and gives independent previews unique heading associations', () => {
  const { container } = render(<><ThemePreview theme={theme()} /><ThemePreview theme={theme()} /></>);
  expect(screen.getAllByText('No templates included')).toHaveLength(2);
  expect(screen.getAllByText('No categories included')).toHaveLength(2);
  const regions = screen.getAllByRole('region');
  expect(new Set(regions.map(region => region.getAttribute('aria-labelledby'))).size).toBe(4);
  expect(new Set([...container.querySelectorAll('[id]')].map(element => element.id)).size).toBe(4);
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
});

it('keeps malformed and duplicate categories visible and recomputes when the theme changes', () => {
  const source = theme({ categories: [category({ name: 'Repeated' }), category({ name: 'Repeated', parentName: 'Repeated' })] });
  const { rerender } = render(<ThemePreview theme={source} />);
  expect(screen.getByRole('status')).toHaveTextContent('Category hierarchy unavailable');
  expect(screen.getAllByText('Repeated', { exact: true })).toHaveLength(2);
  expect(screen.getAllByRole('listitem').every(row => row.style.getPropertyValue('--theme-depth') === '0')).toBe(true);
  rerender(<ThemePreview theme={theme({ categories: [category({ name: 'Valid' })] })} />);
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  expect(screen.queryByText('Repeated')).not.toBeInTheDocument();
  expect(screen.getByText('Valid')).toBeInTheDocument();
});
