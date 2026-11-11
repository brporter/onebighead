import { useEffect } from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { createMemoryRouter, Outlet, RouterProvider } from 'react-router-dom';
import DataContext from '../testUtils/DataContext';
import ItemView from '../../src/views/ItemView';
import { useItems } from '../../src/data/items/useItems';
import type { ItemGateway } from '../../src/data/contracts';
import { itemsApi } from '../../src/api/items';
import { ApiError } from '../../src/api/transport';
import { createMockCategory, createMockCollection, createMockDataContextValue, createMockItem } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';
import type { Item } from '../../src/utils/types';

const item = createMockItem({ categoryId: 1 });

function setup(entry = '/collections/1/items/1') {
  const gateway = { getAll: vi.fn(), getById: vi.fn().mockResolvedValue(item), create: vi.fn().mockResolvedValue({ ...item, id: 2 }),
    update: vi.fn().mockResolvedValue({ ...item, name: 'Saved item' }), delete: vi.fn().mockResolvedValue(undefined) } satisfies ItemGateway;
  const sync = vi.fn().mockResolvedValue(undefined);
  const collection = createMockCollection();
  const context = createMockDataContextValue({ collections: [collection], currentCollection: collection,
    categories: [createMockCategory()], loadCollectionTemplates: vi.fn().mockResolvedValue([]), getCategoryTemplates: vi.fn().mockResolvedValue([]) });
  const record = vi.spyOn(itemsApi, 'recordView').mockResolvedValue(undefined);
  let data!: ReturnType<typeof useItems>;
  function Session() {
    const items = useItems(gateway, sync);
    useEffect(() => { data = items; }, [items]);
    return <DataContext value={{ ...context, ...items }}><Outlet /></DataContext>;
  }
  const router = createMemoryRouter([{ element: <Session />, children: [
    { path: '/collections/:collectionId/items/:itemId', element: <ItemView /> },
    { path: '/collections/1/categories/1', element: <h1>Category items</h1> },
    { path: '/collections/1', element: <h1>Collection items</h1> },
  ] }], { initialEntries: ['/collections/1', entry], initialIndex: 1 });
  const view = render(<RouterProvider router={router} />);
  return { ...view, router, context, gateway, record, getData: () => data };
}

afterEach(() => vi.restoreAllMocks());

it('shows the saved result, subsequent server refreshes, and the refreshed data when editing again', async () => {
  const { gateway, getData, record } = setup();
  await screen.findByRole('heading', { name: item.name });
  await userEvent.click(screen.getByRole('button', { name: 'Edit' }));
  await userEvent.clear(screen.getByLabelText('Name'));
  await userEvent.type(screen.getByLabelText('Name'), 'Saved item');
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
  expect(await screen.findByRole('heading', { name: 'Saved item' })).toBeInTheDocument();
  const refreshed = { ...item, name: 'Updated elsewhere', summary: 'Fresh summary' };
  gateway.getById.mockResolvedValue(refreshed);
  await act(async () => { await getData().refreshLoadedItems({ throwOnError: true }); });
  expect(screen.getByRole('heading', { name: 'Updated elsewhere' })).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Edit' }));
  expect(screen.getByLabelText('Name')).toHaveValue('Updated elsewhere');
  expect(screen.getByLabelText('Summary')).toHaveValue('Fresh summary');
  expect(gateway.update).toHaveBeenCalledOnce();
  expect(record).toHaveBeenCalledExactlyOnceWith(1);
});

it('returns to the category after deletion even though the data store removes the open item', async () => {
  const { gateway, getData } = setup();
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  await screen.findByRole('heading', { name: item.name });
  await userEvent.click(screen.getByRole('button', { name: 'Edit' }));
  await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
  expect(await screen.findByRole('heading', { name: 'Category items' })).toBeInTheDocument();
  expect(gateway.delete).toHaveBeenCalledExactlyOnceWith(1);
  expect(getData().itemDetails.get(1)).toBeNull();
});

it('shows a missing-item page when a previously loaded item is no longer available', async () => {
  const { gateway, getData } = setup();
  await screen.findByRole('heading', { name: item.name });
  gateway.getById.mockRejectedValue(new ApiError('Gone', 404, 'Not Found'));
  await act(async () => { await expect(getData().refreshLoadedItems({ throwOnError: true })).rejects.toThrow('no longer available'); });
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Item not found'));
  expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'View collection' })).toHaveAttribute('href', '/collections/1');
});

it('returns an uncategorized item to its collection', async () => {
  const { gateway, getData } = setup();
  await screen.findByRole('heading', { name: item.name });
  gateway.getById.mockResolvedValue({ ...item, categoryId: null });
  await act(async () => { await getData().refreshLoadedItems({ throwOnError: true }); });
  await userEvent.click(screen.getByRole('button', { name: 'Back to list' }));
  expect(await screen.findByRole('heading', { name: 'Collection items' })).toBeInTheDocument();
});

function unloadPrevented() {
  const event = new Event('beforeunload', { cancelable: true });
  window.dispatchEvent(event);
  return event.defaultPrevented;
}

async function editName(name = 'Unsaved draft') {
  await userEvent.click(await screen.findByRole('button', { name: 'Edit' }));
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: name } });
}

it('guards route links, category navigation and browser history while preserving a rejected draft', async () => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  const { router } = setup();
  await editName();
  expect(unloadPrevented()).toBe(true);
  await userEvent.click(screen.getByRole('link', { name: 'Test Collection' }));
  expect(screen.getByLabelText('Name')).toHaveValue('Unsaved draft');
  await userEvent.click(screen.getByRole('button', { name: 'All Test Category' }));
  expect(router.state.location.pathname).toBe('/collections/1/items/1');
  await act(() => router.navigate(-1));
  expect(screen.getByLabelText('Name')).toHaveValue('Unsaved draft');
  expect(confirm).toHaveBeenCalledTimes(3);
  confirm.mockReturnValue(true);
  await userEvent.click(screen.getByRole('button', { name: '← Back to items' }));
  expect(await screen.findByRole('heading', { name: 'Category items' })).toBeInTheDocument();
  expect(unloadPrevented()).toBe(false);
});

it('protects changing new-item query parameters without treating hash movement as leaving', async () => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  const { router } = setup('/collections/1/items/new?categoryId=1');
  await userEvent.click(await screen.findByText('Start from scratch'));
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'New draft' } });
  await act(() => router.navigate('/collections/1/items/new?categoryId=1#images'));
  expect(confirm).not.toHaveBeenCalled();
  await act(() => router.navigate('/collections/1/items/new'));
  expect(router.state.location.search).toBe('?categoryId=1');
  expect(screen.getByLabelText('Name')).toHaveValue('New draft');
  expect(confirm).toHaveBeenCalledOnce();
  confirm.mockReturnValue(true);
  await act(() => router.navigate('/collections/1/items/new'));
  expect(await screen.findByRole('dialog', { name: 'Choose a Template' })).toBeInTheDocument();
});

it.each(['existing', 'new'])('confirms cancel exactly once for a dirty %s item', async mode => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  const { router } = setup(mode === 'new' ? '/collections/1/items/new?categoryId=1' : undefined);
  if (mode === 'new') {
    await userEvent.click(await screen.findByText('Start from scratch'));
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Unsaved draft' } });
  } else await editName();
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(screen.getByLabelText('Name')).toHaveValue('Unsaved draft');
  confirm.mockReturnValue(true);
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(confirm).toHaveBeenCalledTimes(2);
  expect(screen.queryByLabelText('Name')).not.toBeInTheDocument();
  expect(unloadPrevented()).toBe(false);
  expect(router.state.location.pathname).toBe(mode === 'new' ? '/collections/1/categories/1' : '/collections/1/items/1');
});

it('allows a clean editor to leave without confirmation after an edit is reverted', async () => {
  const confirm = vi.spyOn(window, 'confirm');
  setup();
  await editName();
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: item.name } });
  expect(unloadPrevented()).toBe(false);
  await userEvent.click(screen.getByRole('button', { name: '← Back to items' }));
  expect(await screen.findByRole('heading', { name: 'Category items' })).toBeInTheDocument();
  expect(confirm).not.toHaveBeenCalled();
});

it('blocks navigation during save, preserves failures and releases protection after a successful retry', async () => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  const { gateway, router } = setup();
  const pending = deferred<Item>();
  gateway.update.mockReturnValueOnce(pending.promise);
  await editName();
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
  await userEvent.click(screen.getByRole('button', { name: '← Back to items' }));
  expect(router.state.location.pathname).toBe('/collections/1/items/1');
  expect(unloadPrevented()).toBe(true);
  expect(confirm).not.toHaveBeenCalled();
  await act(async () => pending.reject(new Error('Save failed')));
  expect(screen.getByRole('alert')).toHaveTextContent('Save failed');
  await userEvent.click(screen.getByRole('button', { name: '← Back to items' }));
  expect(confirm).toHaveBeenCalledOnce();
  expect(screen.getByLabelText('Name')).toHaveValue('Unsaved draft');
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
  expect(await screen.findByRole('heading', { name: 'Saved item' })).toBeInTheDocument();
  await waitFor(() => expect(unloadPrevented()).toBe(false));
  await userEvent.click(screen.getByRole('button', { name: '← Back to items' }));
  expect(await screen.findByRole('heading', { name: 'Category items' })).toBeInTheDocument();
  expect(confirm).toHaveBeenCalledOnce();
});

it('returns to the selected category after creating without a second discard confirmation', async () => {
  const confirm = vi.spyOn(window, 'confirm');
  const { gateway } = setup('/collections/1/items/new?categoryId=1');
  const pending = deferred<Item>();
  gateway.create.mockReturnValue(pending.promise);
  await userEvent.click(await screen.findByText('Start from scratch'));
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Created item' } });
  await userEvent.click(screen.getByRole('button', { name: 'Create Item' }));
  await userEvent.click(screen.getByRole('link', { name: 'Test Collection' }));
  expect(screen.getByLabelText('Name')).toBeDisabled();
  expect(confirm).not.toHaveBeenCalled();
  await act(async () => pending.resolve({ ...item, id: 2 }));
  expect(await screen.findByRole('heading', { name: 'Category items' })).toBeInTheDocument();
  expect(confirm).not.toHaveBeenCalled();
  expect(unloadPrevented()).toBe(false);
});

it('guards a clean editor during upload and treats the finished image as an unsaved edit', async () => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  const { context, router } = setup();
  const upload = deferred<{ url: string; key: string }>();
  vi.mocked(context.uploadImage).mockReturnValue(upload.promise);
  await userEvent.click(await screen.findByRole('button', { name: 'Edit' }));
  expect(unloadPrevented()).toBe(false);
  await userEvent.upload(screen.getByLabelText('Choose images'), new File(['image'], 'front.png', { type: 'image/png' }));
  await act(() => router.navigate(-1));
  expect(router.state.location.pathname).toBe('/collections/1/items/1');
  expect(unloadPrevented()).toBe(true);
  expect(confirm).not.toHaveBeenCalled();
  await act(async () => upload.resolve({ url: '/front.png', key: 'front' }));
  await userEvent.click(screen.getByRole('button', { name: '← Back to items' }));
  expect(confirm).toHaveBeenCalledOnce();
  expect(screen.getByRole('img', { name: 'front' })).toBeInTheDocument();
});

it('requires only the delete confirmation and waits for deletion before leaving a dirty editor', async () => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
  const { gateway, router } = setup();
  const deletion = deferred<void>();
  gateway.delete.mockReturnValue(deletion.promise);
  await editName();
  await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
  expect(confirm).toHaveBeenCalledOnce();
  expect(confirm).toHaveBeenCalledWith(`Are you sure you want to delete "${item.name}"?`);
  await act(() => router.navigate(-1));
  expect(router.state.location.pathname).toBe('/collections/1/items/1');
  expect(confirm).toHaveBeenCalledOnce();
  await act(async () => deletion.resolve());
  expect(await screen.findByRole('heading', { name: 'Category items' })).toBeInTheDocument();
  expect(confirm).toHaveBeenCalledOnce();
  await waitFor(() => expect(unloadPrevented()).toBe(false));
});

it('releases navigation after a failed upload when the editor has no unsaved changes', async () => {
  const confirm = vi.spyOn(window, 'confirm');
  const { context } = setup();
  const upload = deferred<{ url: string; key: string }>();
  vi.mocked(context.uploadImage).mockReturnValue(upload.promise);
  await userEvent.click(await screen.findByRole('button', { name: 'Edit' }));
  await userEvent.upload(screen.getByLabelText('Choose images'), new File(['image'], 'front.png', { type: 'image/png' }));
  expect(unloadPrevented()).toBe(true);
  await act(async () => upload.reject(new Error('Upload failed')));
  expect(screen.getByRole('alert')).toHaveTextContent('Upload failed');
  await waitFor(() => expect(unloadPrevented()).toBe(false));
  await userEvent.click(screen.getByRole('button', { name: '← Back to items' }));
  expect(await screen.findByRole('heading', { name: 'Category items' })).toBeInTheDocument();
  expect(confirm).not.toHaveBeenCalled();
});
