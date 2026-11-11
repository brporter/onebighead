import { act, renderHook, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { mergeTemplates, useTemplateCatalog } from '../../src/data/templates/useTemplateCatalog';
import { useTemplateRecommendations } from '../../src/data/templates/useTemplateRecommendations';
import type { ItemTemplate } from '../../src/utils/types';
import type { RequestOptions } from '../../src/api/transport';
import { createMockItemTemplate } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';

const first = createMockItemTemplate({ name: 'Zulu' });
const second = createMockItemTemplate({ itemTemplateId: 2, name: 'Alpha' });
const makePort = () => ({
  loadCollectionTemplates: vi.fn<(id: number, options?: RequestOptions) => Promise<ItemTemplate[]>>().mockResolvedValue([first]),
  fetchItemTemplates: vi.fn<(options?: RequestOptions) => Promise<ItemTemplate[]>>().mockResolvedValue([second]),
});

it('merges and sorts templates without mutating the sources, preferring collection entries', () => {
  const collection = [first];
  const library = [second, { ...first, name: 'Older' }];
  expect(mergeTemplates(collection, library)).toEqual([second, first]);
  expect(collection).toEqual([first]);
  expect(library[1].name).toBe('Older');
});

it('loads a catalog through narrow, cancellable ports', async () => {
  const port = makePort();
  const { result } = renderHook(() => useTemplateCatalog(4, port));
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.data).toEqual({ collection: [first], library: [second], available: [second, first] });
  expect(port.loadCollectionTemplates).toHaveBeenCalledWith(4, { signal: expect.any(AbortSignal) });
  expect(port.fetchItemTemplates).toHaveBeenCalledWith({ signal: port.loadCollectionTemplates.mock.calls[0][1]!.signal });
});

it.each(['collection', 'library'])('exposes %s errors and retries without stale results', async source => {
  const port = makePort();
  const method = source === 'collection' ? port.loadCollectionTemplates : port.fetchItemTemplates;
  method.mockRejectedValueOnce(new Error('Offline'));
  const { result } = renderHook(() => useTemplateCatalog(4, port));
  await waitFor(() => expect(result.current.error).toBe('Offline'));
  expect(result.current.data).toBeNull();
  act(() => result.current.retry());
  await waitFor(() => expect(result.current.data?.available).toHaveLength(2));
  expect(result.current.error).toBeNull();
});

it('clears the old catalog on collection changes and aborts stale work', async () => {
  const port = makePort();
  const pending = deferred<ItemTemplate[]>();
  const { result, rerender, unmount } = renderHook(({ id }) => useTemplateCatalog(id, port), { initialProps: { id: 1 } });
  await waitFor(() => expect(result.current.data).not.toBeNull());
  port.loadCollectionTemplates.mockReturnValueOnce(pending.promise);
  rerender({ id: 2 });
  expect(result.current.data).toBeNull();
  const signal = port.loadCollectionTemplates.mock.calls[1][1]!.signal!;
  rerender({ id: 3 });
  expect(signal.aborted).toBe(true);
  await waitFor(() => expect(result.current.loading).toBe(false));
  await act(async () => pending.resolve([]));
  expect(result.current.data?.collection).toEqual([first]);
  const lastSignal = port.loadCollectionTemplates.mock.calls[2][1]!.signal!;
  unmount();
  expect(lastSignal.aborted).toBe(true);
});

it('loads recommendations only for a category, retries errors, and clears them when leaving it', async () => {
  const port = { getCategoryTemplates: vi.fn<(id: number, options?: RequestOptions) => Promise<number[]>>().mockResolvedValue([1]) };
  const { result, rerender } = renderHook(({ id }) => useTemplateRecommendations(id, port), { initialProps: { id: null as number | null } });
  expect(result.current.loading).toBe(false);
  expect(port.getCategoryTemplates).not.toHaveBeenCalled();
  port.getCategoryTemplates.mockRejectedValueOnce(new Error('Offline'));
  rerender({ id: 3 });
  await waitFor(() => expect(result.current.error).toBe('Offline'));
  act(() => result.current.retry());
  await waitFor(() => expect(result.current.data).toEqual([1]));
  expect(port.getCategoryTemplates).toHaveBeenCalledWith(3, { signal: expect.any(AbortSignal) });
  rerender({ id: null });
  expect(result.current.data).toBeNull();
  expect(result.current.error).toBeNull();
});
