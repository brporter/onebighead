import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import type { bulkUpdatesApi, BulkUpdateJobResponse } from '../../src/api/bulkUpdates';
import { useBulkUpdateMonitor } from '../../src/data/bulkUpdates/useBulkUpdateMonitor';
import { useCollectionBulkUpdate } from '../../src/data/bulkUpdates/useCollectionBulkUpdate';
import { useBulkUpdateSubmission } from '../../src/data/bulkUpdates/useBulkUpdateSubmission';
import { deferred } from '../testUtils/deferred';

const job: BulkUpdateJobResponse = { jobId: 'one', status: 'Queued', totalItems: 3, processedItems: 0, failedItems: 0 };
const done = { ...job, status: 'Completed', processedItems: 3 };
const gateway = () => ({
  getStatus: vi.fn<typeof bulkUpdatesApi.getStatus>(),
  getCollectionStatus: vi.fn<typeof bulkUpdatesApi.getCollectionStatus>(),
});
const tick = (ms = 500) => act(async () => vi.advanceTimersByTimeAsync(ms));
beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe('Bulk update monitoring', () => {
  it('waits for each response before polling again and stops on completion', async () => {
    const api = gateway();
    const pending = deferred<BulkUpdateJobResponse>();
    api.getStatus.mockReturnValueOnce(pending.promise).mockResolvedValueOnce(done);
    const { result } = renderHook(() => useBulkUpdateMonitor(job, api));
    expect(result.current.job).toEqual(job);
    await tick(2500);
    expect(api.getStatus).toHaveBeenCalledOnce();
    await act(async () => pending.resolve({ ...job, status: 'Running', processedItems: 1 }));
    expect(result.current.job?.processedItems).toBe(1);
    await tick();
    expect(result.current.job).toEqual(done);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([null, done, { ...job, status: 'Failed' }, { ...job, status: 'Cancelled' }])('does not poll an inactive job (%s)', (initial) => {
    const api = gateway();
    const { result } = renderHook(() => useBulkUpdateMonitor(initial, api));
    expect(result.current.job).toEqual(initial);
    expect(vi.getTimerCount()).toBe(0);
    expect(api.getStatus).not.toHaveBeenCalled();
  });

  it('stops polling an interrupted job and retains its partial progress', async () => {
    const api = gateway();
    const interrupted = { ...job, status: 'Cancelled', processedItems: 1 };
    api.getStatus.mockResolvedValue(interrupted);
    const { result } = renderHook(() => useBulkUpdateMonitor(job, api));
    await tick(2500);
    expect(result.current.job).toEqual(interrupted);
    expect(api.getStatus).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(['resolve', 'reject'] as const)('ignores a late %s after switching jobs', async settle => {
    const api = gateway();
    const pending = deferred<BulkUpdateJobResponse>();
    api.getStatus.mockReturnValueOnce(pending.promise).mockResolvedValueOnce({ ...done, jobId: 'two' });
    const { result, rerender } = renderHook(({ initial }) => useBulkUpdateMonitor(initial, api), { initialProps: { initial: job } });
    await tick();
    const oldSignal = api.getStatus.mock.calls[0][1]!.signal!;
    rerender({ initial: { ...job, jobId: 'two' } });
    expect(oldSignal.aborted).toBe(true);
    expect(result.current.job?.jobId).toBe('two');
    await act(async () => pending[settle](done));
    expect(result.current.job?.jobId).toBe('two');
    expect(result.current.error).toBeNull();
    await tick();
    expect(result.current.job?.status).toBe('Completed');
  });

  it('cancels requests and scheduled polls on unmount', async () => {
    const api = gateway();
    const pending = deferred<BulkUpdateJobResponse>();
    api.getStatus.mockReturnValue(pending.promise);
    const { unmount } = renderHook(() => useBulkUpdateMonitor(job, api));
    await tick();
    unmount();
    expect(api.getStatus.mock.calls[0][1]!.signal!.aborted).toBe(true);
    await act(async () => pending.resolve(done));
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([new Error('Offline'), 'unexpected failure'])('offers an explicit retry after %s', async error => {
    const api = gateway();
    api.getStatus.mockRejectedValueOnce(error).mockResolvedValueOnce(done);
    const { result } = renderHook(() => useBulkUpdateMonitor(job, api));
    await tick();
    expect(result.current.error).toBe(error instanceof Error ? 'Offline' : 'Failed to check update status');
    expect(vi.getTimerCount()).toBe(0);
    act(() => result.current.retry());
    expect(result.current.error).toBeNull();
    await tick();
    expect(result.current.job).toEqual(done);
  });
});

describe('Collection update discovery', () => {
  it('waits for a collection and cancels discovery on navigation', async () => {
    const api = gateway();
    const pending = deferred<BulkUpdateJobResponse | null>();
    api.getCollectionStatus.mockReturnValue(pending.promise);
    const settled = vi.fn();
    const { result, rerender } = renderHook(({ id }) => useCollectionBulkUpdate(id, api, settled), { initialProps: { id: null as number | null } });
    expect(api.getCollectionStatus).not.toHaveBeenCalled();
    rerender({ id: 1 });
    expect(api.getCollectionStatus).toHaveBeenCalledWith(1, { signal: expect.any(AbortSignal) });
    rerender({ id: null });
    expect(api.getCollectionStatus.mock.calls[0][1]!.signal!.aborted).toBe(true);
    await act(async () => pending.resolve(job));
    expect(result.current.job).toBeNull();
    expect(settled).not.toHaveBeenCalled();
  });

  it('retries discovery, follows the job, and notifies completion only once', async () => {
    const api = gateway();
    api.getCollectionStatus.mockRejectedValueOnce(new Error('Unavailable')).mockResolvedValueOnce(job);
    api.getStatus.mockResolvedValue(done);
    const settled = vi.fn();
    const { result, rerender } = renderHook(({ onSettled }) => useCollectionBulkUpdate(1, api, onSettled), { initialProps: { onSettled: settled } });
    await act(async () => {});
    expect(result.current.error).toBe('Unavailable');
    await act(async () => result.current.retry());
    expect(result.current.error).toBeNull();
    await tick();
    expect(result.current.job).toEqual(done);
    expect(settled).toHaveBeenCalledOnce();
    const replacement = vi.fn();
    rerender({ onSettled: replacement });
    expect(replacement).not.toHaveBeenCalled();
  });

  it('exposes polling errors and retries without starting another discovery', async () => {
    const api = gateway();
    api.getCollectionStatus.mockResolvedValue(job);
    api.getStatus.mockRejectedValueOnce(new Error('Connection lost')).mockResolvedValueOnce({ ...done, status: 'Failed' });
    const settled = vi.fn();
    const { result } = renderHook(() => useCollectionBulkUpdate(1, api, settled));
    await act(async () => {});
    await tick();
    expect(result.current.error).toBe('Connection lost');
    act(() => result.current.retry());
    await tick();
    expect(settled).toHaveBeenCalledOnce();
    expect(api.getCollectionStatus).toHaveBeenCalledOnce();
  });
});

describe('Bulk update submission', () => {
  const request = { scope: 'Collection', collectionId: 1, oldProperties: [], newProperties: [] };

  it('deduplicates submissions until the first one settles', async () => {
    const pending = deferred<BulkUpdateJobResponse>();
    const enqueue = vi.fn<typeof bulkUpdatesApi.enqueue>().mockReturnValue(pending.promise);
    const { result } = renderHook(() => useBulkUpdateSubmission({ enqueue }));
    act(() => {
      void result.current.submit(request);
      void result.current.submit(request);
    });
    expect(enqueue).toHaveBeenCalledOnce();
    expect(result.current.submitting).toBe(true);
    await act(async () => pending.resolve(job));
    expect(result.current.submitting).toBe(false);
    expect(result.current.job).toEqual(job);
    expect(result.current.error).toBeNull();
  });

  it.each([new Error('Unavailable'), 'offline'])('allows retry after a submission failure (%s)', async error => {
    const enqueue = vi.fn<typeof bulkUpdatesApi.enqueue>().mockRejectedValueOnce(error).mockResolvedValueOnce(job);
    const { result } = renderHook(() => useBulkUpdateSubmission({ enqueue }));
    await act(async () => result.current.submit(request));
    expect(result.current.error).toBe(error instanceof Error ? 'Unavailable' : 'Failed to start bulk update');
    expect(result.current.submitting).toBe(false);
    await act(async () => result.current.submit(request));
    expect(result.current.error).toBeNull();
    expect(result.current.job).toEqual(job);
  });

  it.each(['resolve', 'reject'] as const)('aborts on unmount and ignores a late %s', async settle => {
    const pending = deferred<BulkUpdateJobResponse>();
    const enqueue = vi.fn<typeof bulkUpdatesApi.enqueue>().mockReturnValue(pending.promise);
    const { result, unmount } = renderHook(() => useBulkUpdateSubmission({ enqueue }));
    act(() => { void result.current.submit(request); });
    unmount();
    expect(enqueue.mock.calls[0][1]!.signal!.aborted).toBe(true);
    await act(async () => pending[settle](job));
    expect(result.current.job).toBeNull();
    expect(result.current.error).toBeNull();
  });
});
