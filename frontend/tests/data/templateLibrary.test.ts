import { act, renderHook, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useTemplateLibrary } from '../../src/data/templates/useTemplateLibrary';
import { createMockItemTemplate } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';
import type { ItemTemplate } from '../../src/utils/types';

it('loads an isolated catalog, recovers from errors, and ignores replaced and abandoned loads', async () => {
  const first = deferred<ItemTemplate[]>();
  const template = createMockItemTemplate();
  const port = { fetchItemTemplates: vi.fn().mockReturnValueOnce(first.promise).mockRejectedValueOnce(new Error('Offline')).mockResolvedValue([template]), deleteItemTemplate: vi.fn() };
  const { result, unmount } = renderHook(() => useTemplateLibrary(port));
  expect(result.current.loading).toBe(true);
  const firstSignal = port.fetchItemTemplates.mock.calls[0][0].signal;
  act(() => result.current.refresh());
  await waitFor(() => expect(result.current.error).toBe('Offline'));
  expect(firstSignal.aborted).toBe(true);
  await act(async () => first.resolve([template]));
  expect(result.current.data).toBeNull();
  act(() => result.current.refresh());
  await waitFor(() => expect(result.current.data).toEqual([template]));
  const signal = port.fetchItemTemplates.mock.calls.slice(-1)[0][0].signal;
  unmount();
  expect(signal.aborted).toBe(true);
});

it('serializes deletion, retains the catalog on failure, and refreshes after a successful retry', async () => {
  const template = createMockItemTemplate();
  const pending = deferred<void>();
  const port = { fetchItemTemplates: vi.fn().mockResolvedValueOnce([template]).mockResolvedValue([]), deleteItemTemplate: vi.fn().mockReturnValueOnce(pending.promise).mockResolvedValue(undefined) };
  const { result } = renderHook(() => useTemplateLibrary(port));
  await waitFor(() => expect(result.current.data).toEqual([template]));
  act(() => { void result.current.remove(1); void result.current.remove(1); });
  expect(result.current.deleting).toBe(true);
  expect(port.deleteItemTemplate).toHaveBeenCalledTimes(1);
  await act(async () => pending.reject('Offline'));
  expect(result.current.deleteError).toBe('Unable to delete template');
  expect(result.current.data).toEqual([template]);
  await act(async () => { await result.current.remove(1); });
  await waitFor(() => expect(result.current.data).toEqual([]));
  expect(result.current.deleteError).toBeNull();
  expect(port.fetchItemTemplates).toHaveBeenCalledTimes(2);
});

it('does not refresh a library abandoned during deletion', async () => {
  const pending = deferred<void>();
  const port = { fetchItemTemplates: vi.fn().mockResolvedValue([]), deleteItemTemplate: vi.fn().mockReturnValue(pending.promise) };
  const { result, unmount } = renderHook(() => useTemplateLibrary(port));
  await waitFor(() => expect(result.current.loading).toBe(false));
  act(() => { void result.current.remove(1); });
  unmount();
  await act(async () => pending.resolve());
  expect(port.fetchItemTemplates).toHaveBeenCalledTimes(1);
});
