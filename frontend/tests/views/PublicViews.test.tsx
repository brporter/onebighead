import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom';
import PublicCollectionsView from '../../src/views/PublicCollectionsView';
import PublicCollectionDetailView from '../../src/views/PublicCollectionDetailView';
import PublicItemView from '../../src/views/PublicItemView';
import { publicApi } from '../../src/api';
import type { PublicCollectionDetail, PublicItem } from '../../src/api/public';
import { deferred } from '../testUtils/deferred';
import type { ReactElement } from 'react';

vi.mock('../../src/api', () => ({ publicApi: {
  getCollections: vi.fn(), getCollection: vi.fn(), getItems: vi.fn(), getItem: vi.fn(),
} }));

const collection = { id: 2, name: 'Books', description: 'Stories to keep', heroImageUrl: '/books.jpg', slug: 'books' };
const detail: PublicCollectionDetail = { collection, categories: [
  { id: 10, name: 'Fiction', parentCategoryId: null, isSystem: false, itemTemplateIds: [] },
  { id: 11, name: 'Mysteries', parentCategoryId: 10, isSystem: false, itemTemplateIds: [] },
] };
const item: PublicItem = { id: 3, name: 'A book', summary: 'A story', description: 'A longer description',
  images: [{ url: '/cover.jpg', alt: 'Front cover' }, { url: '/back.jpg', alt: null }],
  properties: [{ category: 'Edition', name: 'Year', value: '1960' }, { category: '', name: 'Author', value: 'Writer' }],
  categoryId: 10, categoryName: 'Fiction', templateKey: null };

function view(element: ReactElement, url: string, path: string) {
  return render(<MemoryRouter initialEntries={[url]}>
    <Link to="/public/library/collections/4">Another collection</Link>
    <Link to="/public/library/items/4">Another item</Link>
    <Routes><Route path={path} element={element} /></Routes>
  </MemoryRouter>);
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(publicApi.getCollections).mockResolvedValue([collection]);
  vi.mocked(publicApi.getCollection).mockResolvedValue(detail);
  vi.mocked(publicApi.getItems).mockResolvedValue([]);
  vi.mocked(publicApi.getItem).mockResolvedValue(item);
});

describe('public collections', () => {
  it('shows loading then cards with and without optional content', async () => {
    vi.mocked(publicApi.getCollections).mockResolvedValue([collection, { ...collection, id: 4, name: 'Records', description: '', heroImageUrl: null }]);
    view(<PublicCollectionsView />, '/public/library', '/public/:slug');
    expect(screen.getByRole('status')).toHaveTextContent('Loading collections');
    expect(await screen.findByRole('link', { name: 'Books Stories to keep' })).toHaveAttribute('href', '/public/library/collections/2');
    expect(screen.getByRole('link', { name: 'Records' })).toHaveAttribute('href', '/public/library/collections/4');
    expect(screen.getByRole('heading', { name: 'Books', level: 2 })).toBeInTheDocument();
  });
  it('reports API failures', async () => {
    vi.mocked(publicApi.getCollections).mockRejectedValue(new Error('Offline'));
    view(<PublicCollectionsView />, '/public/library', '/public/:slug');
    expect(await screen.findByRole('alert')).toHaveTextContent('Offline');
  });
  it('shows an empty state for an empty response', async () => {
    vi.mocked(publicApi.getCollections).mockResolvedValue([]);
    view(<PublicCollectionsView />, '/public/library', '/public/:slug');
    expect(await screen.findByText('No public collections available.')).toBeInTheDocument();
  });
  it('does not fetch without a workspace slug', async () => {
    view(<PublicCollectionsView />, '/missing', '/missing');
    expect(await screen.findByText('No public collections available.')).toBeInTheDocument();
    expect(publicApi.getCollections).not.toHaveBeenCalled();
  });
});

describe('public collection detail', () => {
  it('separates collection and item loading states and displays item cards', async () => {
    const pending = deferred<Awaited<ReturnType<typeof publicApi.getItems>>>();
    vi.mocked(publicApi.getItems).mockReturnValue(pending.promise);
    view(<PublicCollectionDetailView />, '/public/library/collections/2', '/public/:slug/collections/:collectionId');
    expect(screen.getByRole('status')).toHaveTextContent('Loading collection');
    await screen.findByRole('heading', { name: 'Books' });
    expect(screen.getByRole('status')).toHaveTextContent('Loading items');
    await act(async () => pending.resolve([
      { id: 3, name: 'A book', summary: 'A story', primaryImageUrl: '/book.jpg', categoryId: 10 },
      { id: 4, name: 'Another book', summary: '', primaryImageUrl: null, categoryId: null },
    ]));
    expect(await screen.findByRole('link', { name: 'A book A story' })).toHaveAttribute('href', '/public/library/items/3');
    expect(screen.getByRole('link', { name: /All Collections/ })).toHaveAttribute('href', '/public/library');
    expect(screen.getByRole('heading', { level: 3, name: 'Another book' })).toBeInTheDocument();
  });
  it('surfaces item request failures instead of claiming that the collection is empty', async () => {
    vi.mocked(publicApi.getItems).mockRejectedValue(new Error('Items are temporarily unavailable'));
    view(<PublicCollectionDetailView />, '/public/library/collections/2', '/public/:slug/collections/:collectionId');
    expect(await screen.findByRole('alert')).toHaveTextContent('Items are temporarily unavailable');
    expect(screen.queryByText('No items in this view.')).not.toBeInTheDocument();
  });
  it('shows collection errors', async () => {
    vi.mocked(publicApi.getCollection).mockRejectedValue(new Error('Unavailable'));
    view(<PublicCollectionDetailView />, '/public/library/collections/2', '/public/:slug/collections/:collectionId');
    expect(await screen.findByRole('alert')).toHaveTextContent('Unavailable');
  });
  it.each([
    ['/missing', '/missing'],
    ['/public/library/collections/2invalid', '/public/:slug/collections/:collectionId'],
  ])('rejects missing or invalid route parameters (%s)', async (url, path) => {
    view(<PublicCollectionDetailView />, url, path);
    expect(await screen.findByRole('alert')).toHaveTextContent('Collection not found');
    expect(publicApi.getCollection).not.toHaveBeenCalled();
    expect(publicApi.getItems).not.toHaveBeenCalled();
  });
  it('supports nested category selection, toggling, all items, and resets when the collection changes', async () => {
    const user = userEvent.setup();
    view(<PublicCollectionDetailView />, '/public/library/collections/2', '/public/:slug/collections/:collectionId');
    const child = await screen.findByRole('button', { name: 'Mysteries' });
    await user.click(child);
    expect(child).toHaveAttribute('aria-pressed', 'true');
    await waitFor(() => expect(publicApi.getItems).toHaveBeenLastCalledWith('library', 2, 11, { signal: expect.any(AbortSignal) }));
    await user.click(child);
    await waitFor(() => expect(publicApi.getItems).toHaveBeenLastCalledWith('library', 2, undefined, { signal: expect.any(AbortSignal) }));
    await user.click(screen.getByRole('button', { name: 'Fiction' }));
    await user.click(screen.getByRole('button', { name: 'All Items' }));
    expect(screen.getByRole('button', { name: 'All Items' })).toHaveAttribute('aria-pressed', 'true');
    await user.click(child);
    await user.click(screen.getByRole('link', { name: 'Another collection' }));
    await waitFor(() => expect(publicApi.getItems).toHaveBeenLastCalledWith('library', 4, undefined, { signal: expect.any(AbortSignal) }));
    expect(await screen.findByRole('button', { name: 'All Items' })).toHaveAttribute('aria-pressed', 'true');
  });
  it('renders collections without categories or descriptions', async () => {
    vi.mocked(publicApi.getCollection).mockResolvedValue({ collection: { ...collection, description: '' }, categories: [] });
    view(<PublicCollectionDetailView />, '/public/library/collections/2', '/public/:slug/collections/:collectionId');
    expect(await screen.findByText('No items in this view.')).toBeInTheDocument();
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
  });
});

describe('public item', () => {
  it('uses shared property and image components and a deterministic back link', async () => {
    const user = userEvent.setup();
    view(<PublicItemView />, '/public/library/items/3', '/public/:slug/items/:itemId');
    expect(screen.getByRole('status')).toHaveTextContent('Loading item');
    expect(await screen.findByRole('heading', { name: 'A book', level: 1 })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /All Collections/ })).toHaveAttribute('href', '/public/library');
    expect(screen.getByRole('heading', { name: 'Edition', level: 2 })).toBeInTheDocument();
    expect(screen.getByText('1960')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Other' })).toBeInTheDocument();
    expect(screen.getByRole('img')).toHaveAttribute('src', '/cover.jpg');
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByRole('img')).toHaveAttribute('src', '/back.jpg');
    vi.mocked(publicApi.getItem).mockResolvedValue({ ...item, id: 4, images: [{ url: '/new.jpg', alt: null }] });
    await user.click(screen.getByRole('link', { name: 'Another item' }));
    await waitFor(() => expect(screen.getByRole('img')).toHaveAttribute('src', '/new.jpg'));
  });
  it('renders items without optional content', async () => {
    vi.mocked(publicApi.getItem).mockResolvedValue({ ...item, categoryName: null, summary: '', description: '', images: [], properties: [] });
    view(<PublicItemView />, '/public/library/items/3', '/public/:slug/items/:itemId');
    await screen.findByRole('heading', { name: 'A book' });
    expect(screen.queryByRole('region')).not.toBeInTheDocument();
    expect(screen.queryByText('A story')).not.toBeInTheDocument();
  });
  it('reports item errors', async () => {
    vi.mocked(publicApi.getItem).mockRejectedValue(new Error('Not public'));
    view(<PublicItemView />, '/public/library/items/3', '/public/:slug/items/:itemId');
    expect(await screen.findByRole('alert')).toHaveTextContent('Not public');
  });
  it.each([
    ['/missing', '/missing'],
    ['/public/library/items/1bad', '/public/:slug/items/:itemId'],
  ])('rejects missing or invalid item parameters (%s)', async (url, path) => {
    view(<PublicItemView />, url, path);
    expect(await screen.findByRole('alert')).toHaveTextContent('Item not found');
    expect(publicApi.getItem).not.toHaveBeenCalled();
  });
});
