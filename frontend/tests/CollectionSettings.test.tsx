import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import DataContext from './testUtils/DataContext';
import { CollectionSettings } from '../src/components/collection/CollectionSettings';
import { createMockCollection, createMockDataContextValue } from './testUtils/factories';
import { deferred } from './testUtils/deferred';

vi.mock('../src/contexts/usePublish', () => ({ usePublish: () => ({ requestPublish: vi.fn(), requestUnpublish: vi.fn() }) }));
afterEach(() => vi.restoreAllMocks());

it('distinguishes loading, failed and empty collection reads and retries through the data port', async () => {
  const user = userEvent.setup();
  const context = createMockDataContextValue({ collections: [], collectionsLoading: true });
  const status = vi.fn();
  const view = (state: typeof context) => <DataContext value={state}><CollectionSettings isAdmin onStatusChange={status} /></DataContext>;
  const { rerender } = render(view(context));
  expect(screen.getByRole('status')).toHaveTextContent('Loading collections');
  rerender(view({ ...context, collectionsLoading: false, collectionsError: 'Offline' }));
  expect(screen.getByRole('alert')).toHaveTextContent('Offline');
  await user.click(screen.getByRole('button', { name: 'Try again' }));
  expect(context.loadCollections).toHaveBeenCalledTimes(2);
  rerender(view({ ...context, collectionsLoading: false }));
  expect(screen.getByRole('status')).toHaveTextContent('No collections yet');
});

it('serializes deletion, reports failure and retries without refreshing already-updated data', async () => {
  const user = userEvent.setup();
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  const pending = deferred<void>();
  const context = createMockDataContextValue({ collections: [createMockCollection({ name: 'Books' }), createMockCollection({ collectionId: 2 })],
    deleteCollection: vi.fn().mockReturnValueOnce(pending.promise).mockResolvedValue(undefined) });
  const status = vi.fn();
  render(<DataContext value={context}><CollectionSettings isAdmin onStatusChange={status} /></DataContext>);
  const card = within(screen.getByRole('article', { name: 'Books' }));
  await user.dblClick(card.getByRole('button', { name: 'Delete' }));
  expect(context.deleteCollection).toHaveBeenCalledOnce();
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: true });
  for (const button of screen.getAllByRole('button')) expect(button).toBeDisabled();
  await act(async () => pending.reject('unavailable'));
  expect(screen.getByRole('alert')).toHaveTextContent('Failed to delete collection');
  await user.click(card.getByRole('button', { name: 'Delete' }));
  expect(context.deleteCollection).toHaveBeenCalledTimes(2);
  expect(context.loadCollections).toHaveBeenCalledOnce();
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: false });
});

it('offers recovery when an open collection disappears from the shared data', async () => {
  const user = userEvent.setup();
  const context = createMockDataContextValue({ collections: [createMockCollection({ description: undefined })] });
  const status = vi.fn();
  const view = (state: typeof context) => <DataContext value={state}><CollectionSettings isAdmin onStatusChange={status} /></DataContext>;
  const { rerender } = render(view(context));
  await user.click(screen.getByRole('button', { name: 'Edit' }));
  await user.type(screen.getByRole('textbox', { name: 'Name' }), ' revised');
  rerender(view({ ...context, collections: [] }));
  expect(screen.getByRole('status')).toHaveTextContent('This collection is no longer available');
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: false });
  await user.click(screen.getByRole('button', { name: 'Back to collections' }));
  expect(screen.getByRole('status')).toHaveTextContent('No collections yet');
});
