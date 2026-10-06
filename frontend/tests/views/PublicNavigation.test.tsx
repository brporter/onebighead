import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import PublicCollectionsView from '../../src/views/PublicCollectionsView';
import PublicCollectionDetailView from '../../src/views/PublicCollectionDetailView';
import { publicApi } from '../../src/api';
vi.mock('../../src/api', () => ({ publicApi: { getCollections: vi.fn(), getCollection: vi.fn(), getItems: vi.fn() } }));

describe('public navigation', () => {
  it('uses real collection links that support browser navigation', async () => {
    vi.mocked(publicApi.getCollections).mockResolvedValue([{ id: 2, name: 'Books', description: 'My books', heroImageUrl: null }] as Awaited<ReturnType<typeof publicApi.getCollections>>);
    render(<MemoryRouter initialEntries={['/public/library']}><Routes><Route path="/public/:slug" element={<PublicCollectionsView />} /></Routes></MemoryRouter>);
    expect(await screen.findByRole('link', { name: 'Books My books' })).toHaveAttribute('href', '/public/library/collections/2');
  });

  it('uses real item links in public collections', async () => {
    vi.mocked(publicApi.getCollection).mockResolvedValue({ collection: { id: 2, name: 'Books', description: '', heroImageUrl: null, slug: 'books' }, categories: [] });
    vi.mocked(publicApi.getItems).mockResolvedValue([{ id: 3, name: 'A book', summary: 'Summary' }] as Awaited<ReturnType<typeof publicApi.getItems>>);
    render(<MemoryRouter initialEntries={['/public/library/collections/2']}><Routes><Route path="/public/:slug/collections/:collectionId" element={<PublicCollectionDetailView />} /></Routes></MemoryRouter>);
    expect(await screen.findByRole('link', { name: 'A book Summary' })).toHaveAttribute('href', '/public/library/items/3');
  });
});
