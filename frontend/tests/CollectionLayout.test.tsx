import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { CollectionLayout, CollectionHeader } from '../src/components/collection';

afterEach(() => vi.restoreAllMocks());

describe('Collection layout', () => {
  it.each([false, true])('keeps content and a persistent navigation toggle available (narrow: %s)', async narrow => {
    vi.spyOn(window, 'matchMedia').mockReturnValue({ matches: narrow } as MediaQueryList);
    render(<CollectionLayout sidebar={<p>Category tree</p>} header={<h1>Collection</h1>}><p>Items</p></CollectionLayout>);
    expect(screen.getByRole('main')).toHaveTextContent('Items');
    const toggle = screen.getByRole('button', { name: narrow ? 'Expand sidebar' : 'Collapse categories' });
    expect(toggle).toHaveAttribute('aria-expanded', String(!narrow));
    const controlled = document.getElementById(toggle.getAttribute('aria-controls')!);
    expect(controlled).toBeInTheDocument();
    expect(controlled?.textContent).toBe(narrow ? '' : 'Category tree');

    await userEvent.click(toggle);
    expect(toggle).toHaveFocus();
    expect(toggle).toHaveAttribute('aria-expanded', String(narrow));
    expect(controlled?.textContent).toBe(narrow ? 'Category tree' : '');
    expect(screen.getByRole('main')).toHaveTextContent('Items');
  });
});

describe('Collection header', () => {
  it('provides semantic navigation, a single title and supplied actions', () => {
    render(<MemoryRouter><CollectionHeader collection={{ name: 'My books', description: 'Read and remember.' }}
      homeHref="/collections/1" showAllCollections actions={<button>Publish</button>} /></MemoryRouter>);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('My books');
    expect(screen.getByRole('link', { name: 'My books' })).toHaveAttribute('href', '/collections/1');
    expect(screen.getByRole('link', { name: /All Collections/ })).toHaveAttribute('href', '/collections');
    expect(screen.getByText('Read and remember.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Publish' })).toBeInTheDocument();
  });

  it('renders a dashboard title without empty descriptions or navigation', () => {
    render(<MemoryRouter><CollectionHeader collection={{ name: 'My books', description: '' }} showAllCollections={false} /></MemoryRouter>);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('My books');
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });
});
