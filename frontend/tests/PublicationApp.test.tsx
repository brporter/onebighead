import { StrictMode, type ReactNode } from 'react';
import { act, render, renderHook, screen, waitFor } from '@testing-library/react';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import userEvent from '@testing-library/user-event';
import { PublishProvider } from '../src/contexts/PublishContext';
import { usePublish } from '../src/contexts/usePublish';
import { useUser } from '../src/contexts/useUser';
import { useCollectionsData as useDataHook } from '../src/contexts/useData';
import { useToast } from '../src/contexts/useToast';
import { PublishApp } from '../src/components/common/PublishApp';
import { publishManagerApi } from '../src/api/publishManager';
import { createMockCurrentUser, createMockCollection, createMockDataContextValue } from './testUtils/factories';
import { saved } from './testUtils/publication';
import { deferred } from './testUtils/deferred';
import type { ExecuteResponse, EntityRef } from '../src/utils/types';

const useData = useDataHook as () => import('./testUtils/dataTypes').DataContextValue;

vi.mock('../src/contexts/useUser', () => ({ useUser: vi.fn() }));
vi.mock('../src/contexts/useData', async () => {
  const { mockDataHooks } = await import('./testUtils/mockDataHooks');
  return mockDataHooks({ useData: vi.fn() });
});
vi.mock('../src/contexts/useToast', () => ({ useToast: vi.fn() }));
const user = createMockCurrentUser();
const refetch = vi.fn().mockResolvedValue(undefined);
const showToast = vi.fn();
function wrapper({ children }: { children: ReactNode }) { return <StrictMode><PublishProvider>{children}</PublishProvider></StrictMode>; }
function userWorkspace(workspaceId: number | null) {
  vi.mocked(useUser).mockReturnValue({ user: workspaceId === null ? null : { ...user, activeWorkspace: { ...user.activeWorkspace!, workspaceId } }, loading: false,
    error: null, signedOut: false, refetch, logout: vi.fn() });
}
beforeEach(() => {
  vi.clearAllMocks();
  userWorkspace(1);
  vi.mocked(useData).mockReturnValue(createMockDataContextValue({ currentCollection: createMockCollection() }));
  vi.mocked(useToast).mockReturnValue({ showToast, dismissToast: vi.fn(), toasts: [] });
  vi.spyOn(publishManagerApi, 'preflight').mockResolvedValue({ ready: true, requirements: [] });
  vi.spyOn(publishManagerApi, 'execute').mockResolvedValue(saved);
});
afterEach(() => vi.restoreAllMocks());

describe('publication request ownership', () => {
  it('clones and deduplicates entity references, preserving the active request and guarding stale clears', () => {
    const { result } = renderHook(usePublish, { wrapper });
    const entities: EntityRef[] = [{ type: 'item', id: 4 }, { type: 'item', id: 4 }];
    act(() => result.current.requestPublish(entities));
    const first = result.current.pendingRequest!;
    entities[0].id = 99;
    expect(first.entities).toEqual([{ type: 'item', id: 4 }]);
    act(() => result.current.requestUnpublish([{ type: 'category', id: 2 }]));
    expect(result.current.pendingRequest).toBe(first);
    act(() => result.current.clearIntent(999));
    expect(result.current.pendingRequest).toBe(first);
    act(() => result.current.clearIntent(first.requestId));
    act(() => result.current.requestUnpublish([{ type: 'category', id: 2 }]));
    expect(result.current.pendingRequest).toMatchObject({ action: 'unpublish', workspaceId: 1 });
    act(() => result.current.clearIntent(first.requestId));
    expect(result.current.pendingRequest).not.toBeNull();
  });
  it('rejects empty and anonymous requests and retires requests across workspace changes', () => {
    const { result, rerender } = renderHook(usePublish, { wrapper });
    act(() => result.current.requestPublish([]));
    expect(result.current.pendingRequest).toBeNull();
    act(() => result.current.requestPublish([{ type: 'item', id: 4 }]));
    const staleRequest = result.current.requestPublish;
    userWorkspace(2); rerender();
    expect(result.current.pendingRequest).toBeNull();
    act(() => staleRequest([{ type: 'item', id: 8 }]));
    expect(result.current.pendingRequest).toBeNull();
    userWorkspace(1); rerender();
    expect(result.current.pendingRequest).toBeNull();
    userWorkspace(null); rerender();
    act(() => result.current.requestPublish([{ type: 'item', id: 4 }]));
    expect(result.current.pendingRequest).toBeNull();
  });
  it('requires its provider', () => {
    expect(() => renderHook(usePublish)).toThrow('usePublish must be used within a PublishProvider');
  });
});

function Controls() {
  const { requestPublish } = usePublish();
  return <button onClick={() => requestPublish([{ type: 'item', id: 4 }])}>Publish Dune</button>;
}
function app() { return render(<PublishProvider><Controls /><PublishApp /></PublishProvider>); }

describe('publication application wiring', () => {
  it('waits for all refreshes including a new gallery URL before notifying and closing', async () => {
    vi.mocked(publishManagerApi.execute).mockResolvedValue({ ...saved, workspaceSlugSet: 'library' });
    const data = vi.mocked(useData)();
    const pending = deferred<void>();
    vi.mocked(data.refreshLoadedItems).mockReturnValue(pending.promise);
    app();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Publish Dune' }));
    await waitFor(() => expect(data.refreshLoadedItems).toHaveBeenCalledTimes(1));
    expect(data.loadCollections).toHaveBeenCalledWith({ signal: expect.any(AbortSignal), throwOnError: true });
    expect(data.loadCategoriesForCollection).toHaveBeenCalledWith(1, { signal: expect.any(AbortSignal), throwOnError: true });
    expect(refetch).toHaveBeenCalledWith({ throwOnError: true });
    expect(showToast).not.toHaveBeenCalled();
    await act(async () => pending.resolve());
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(showToast).toHaveBeenCalledWith('Dune published.', undefined);
  });
  it('refreshes without a selected collection and skips unnecessary session refreshes', async () => {
    const data = createMockDataContextValue();
    vi.mocked(useData).mockReturnValue(data);
    app();
    await userEvent.click(screen.getByRole('button', { name: 'Publish Dune' }));
    await waitFor(() => expect(showToast).toHaveBeenCalledTimes(1));
    expect(data.loadCategoriesForCollection).not.toHaveBeenCalled();
    expect(refetch).not.toHaveBeenCalled();
  });
  it('exposes a required refresh failure and can dismiss the saved request', async () => {
    vi.mocked(vi.mocked(useData)().loadCollections).mockRejectedValue(new Error('Offline'));
    app();
    await userEvent.click(screen.getByRole('button', { name: 'Publish Dune' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Close' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(showToast).not.toHaveBeenCalled();
  });
  it('aborts old workspace execution and ignores its late response', async () => {
    const write = deferred<ExecuteResponse>();
    vi.mocked(publishManagerApi.execute).mockReturnValueOnce(write.promise);
    const view = app();
    await userEvent.click(screen.getByRole('button', { name: 'Publish Dune' }));
    await waitFor(() => expect(publishManagerApi.execute).toHaveBeenCalledTimes(1));
    userWorkspace(2);
    view.rerender(<PublishProvider><Controls /><PublishApp /></PublishProvider>);
    expect(vi.mocked(publishManagerApi.execute).mock.calls[0][2]!.signal!.aborted).toBe(true);
    await act(async () => write.resolve(saved));
    expect(showToast).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Publish Dune' }));
    await waitFor(() => expect(showToast).toHaveBeenCalledTimes(1));
    expect(publishManagerApi.execute).toHaveBeenLastCalledWith(2, expect.anything(), expect.anything());
  });
});
