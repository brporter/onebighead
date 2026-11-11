import { act, renderHook, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useSupportConversation } from '../../src/data/support/useSupportConversation';
import { useSupportQueue } from '../../src/data/support/useSupportQueue';
import { supportReply, supportRequest } from '../testUtils/support';
import { deferred } from '../testUtils/deferred';
import type { SupportSessionPort, SupportQueuePort, SupportQueueQuery } from '../../src/data/support/ports';
import type { SupportReply, SupportRequestListResponse } from '../../src/api/support';

it('keeps receipt errors independent of a readable conversation and retries acknowledgement', async () => {
  const gateway: SupportSessionPort = { read: vi.fn().mockResolvedValue(supportRequest()), reply: vi.fn(), remove: vi.fn(), markRead: vi.fn().mockRejectedValueOnce(new Error('Receipt failed')).mockResolvedValue(undefined) };
  const request = supportRequest({ unreadCount: 1 });
  const { result } = renderHook(() => useSupportConversation(request, gateway, vi.fn()));
  await waitFor(() => expect(result.current.receipt.error).toBe('Receipt failed'));
  expect(result.current.request).toEqual(request);
  act(() => result.current.receipt.retry());
  await waitFor(() => expect(result.current.receipt.data).toBe(true));
  expect(gateway.markRead).toHaveBeenCalledTimes(2);
  expect(gateway.markRead).toHaveBeenLastCalledWith(1);
});

it('validates reply text, serializes competing mutations and retains a failed reply for retry', async () => {
  const pending = deferred<SupportReply>();
  const gateway: SupportSessionPort = { read: vi.fn().mockResolvedValue(supportRequest()), reply: vi.fn().mockReturnValueOnce(pending.promise).mockResolvedValue(supportReply()), remove: vi.fn(), changeStatus: vi.fn(), markRead: vi.fn() };
  const { result } = renderHook(() => useSupportConversation(supportRequest({ status: 'Resolved' }), gateway, vi.fn()));
  expect(gateway.markRead).not.toHaveBeenCalled();
  expect(result.current.dirty).toBe(false);
  act(() => result.current.setReplyText(' '));
  await act(() => result.current.sendReply());
  expect(result.current.error).toBe('Write a reply before sending.');
  expect(gateway.reply).not.toHaveBeenCalled();
  act(() => result.current.setReplyText('  Additional information  '));
  expect(result.current.dirty).toBe(true);
  let first!: Promise<void>;
  act(() => { first = result.current.sendReply(); void result.current.sendReply(); void result.current.changeStatus('Closed'); void result.current.remove(); });
  expect(gateway.reply).toHaveBeenCalledExactlyOnceWith(1, { message: 'Additional information' });
  expect(gateway.remove).not.toHaveBeenCalled();
  expect(gateway.changeStatus).not.toHaveBeenCalled();
  expect(result.current.pending).toBe(true);
  await act(async () => { pending.reject('offline'); await first; });
  expect(result.current.error).toBe('Failed to send reply');
  expect(result.current.replyText).toBe('  Additional information  ');
  await act(() => result.current.sendReply());
  expect(result.current.request.status).toBe('Open');
  expect(result.current.replyText).toBe('');
  expect(result.current.dirty).toBe(false);
});

it('uses the confirmed status, preserves conversation details and retries failed deletion', async () => {
  const done = vi.fn();
  const gateway: SupportSessionPort = { read: vi.fn().mockResolvedValue(supportRequest()),
    reply: vi.fn(), remove: vi.fn().mockRejectedValueOnce(new Error('Delete failed')).mockResolvedValue(undefined),
    changeStatus: vi.fn().mockRejectedValueOnce(null).mockResolvedValue(supportRequest({ status: 'Resolved', updatedAt: '2026-11-03T12:00:00Z' })),
  };
  const original = supportRequest({ replies: [supportReply()] });
  const { result } = renderHook(() => useSupportConversation(original, gateway, done));
  act(() => result.current.setReplyText('Unsent'));
  await act(() => result.current.changeStatus('Closed'));
  expect(result.current.error).toBe('Failed to update status');
  await act(() => result.current.changeStatus('Closed'));
  expect(result.current.request).toEqual({ ...original, status: 'Resolved', updatedAt: '2026-11-03T12:00:00Z' });
  expect(result.current.replyText).toBe('Unsent');
  await act(() => result.current.remove());
  expect(result.current.error).toBe('Delete failed');
  expect(done).not.toHaveBeenCalled();
  await act(() => result.current.remove());
  expect(done).toHaveBeenCalledOnce();
});

it('rejects unsupported status changes and changes to deleted requests', async () => {
  const gateway = { read: vi.fn(), reply: vi.fn(), remove: vi.fn() };
  const { result, unmount } = renderHook(() => useSupportConversation(supportRequest(), gateway, vi.fn()));
  await act(() => result.current.changeStatus('Closed'));
  expect(result.current.error).toBe('Status changes are unavailable.');
  unmount();
  const deleted = renderHook(() => useSupportConversation(supportRequest({ isDeleted: true }), gateway, vi.fn()));
  await act(() => deleted.result.current.sendReply());
  expect(deleted.result.current.error).toBe('This request has been deleted.');
  await act(() => deleted.result.current.remove());
  expect(gateway.remove).not.toHaveBeenCalled();
  expect(gateway.reply).not.toHaveBeenCalled();
});

it('does not return from a replacement conversation when an old deletion completes', async () => {
  const pending = deferred<void>();
  const done = vi.fn();
  const { result, unmount } = renderHook(() => useSupportConversation(supportRequest(), { read: vi.fn(), reply: vi.fn(), remove: () => pending.promise }, done));
  let removing!: Promise<void>;
  act(() => { removing = result.current.remove(); });
  unmount();
  await act(async () => { pending.resolve(); await removing; });
  expect(done).not.toHaveBeenCalled();
});

it('cancels queue searches, ignores late results and corrects pages after deletion', async () => {
  const first = deferred<SupportRequestListResponse>();
  const gateway: SupportQueuePort = { list: vi.fn().mockReturnValueOnce(first.promise).mockResolvedValue({ items: [], total: 0, limit: 20, offset: 20 }), remove: vi.fn().mockResolvedValue(undefined) };
  const changePage = vi.fn();
  const query: SupportQueueQuery = { page: 0, status: '', includeDeleted: false };
  const { result, rerender } = renderHook(({ query }) => useSupportQueue(query, gateway, changePage), { initialProps: { query } });
  const firstSignal = vi.mocked(gateway.list).mock.calls[0][1]!.signal!;
  expect(gateway.list).toHaveBeenCalledWith({ status: undefined, includeDeleted: false, limit: 20, offset: 0 }, { signal: firstSignal });
  rerender({ query: { page: 1, status: 'Closed', includeDeleted: true } });
  await waitFor(() => expect(changePage).toHaveBeenCalledWith(0));
  expect(firstSignal.aborted).toBe(true);
  await act(async () => first.resolve({ items: [supportRequest()], total: 100, limit: 20, offset: 0 }));
  expect(result.current.data?.total).toBe(0);
  expect(result.current.totalPages).toBe(1);
  expect(gateway.list).toHaveBeenLastCalledWith({ status: 'Closed', includeDeleted: true, limit: 20, offset: 20 }, { signal: expect.any(AbortSignal) });
});

it('serializes queue deletions and reloads server totals only after success', async () => {
  const pending = deferred<void>();
  const gateway: SupportQueuePort = { list: vi.fn().mockResolvedValue({ items: [supportRequest()], total: 41, limit: 20, offset: 0 }), remove: vi.fn().mockReturnValueOnce(pending.promise).mockResolvedValue(undefined) };
  const query = { page: 0, status: '', includeDeleted: false };
  const { result } = renderHook(() => useSupportQueue(query, gateway, vi.fn()));
  await waitFor(() => expect(result.current.data).not.toBeNull());
  expect(result.current.totalPages).toBe(3);
  let first!: Promise<void>;
  act(() => { first = result.current.remove(1); void result.current.remove(2); });
  expect(gateway.remove).toHaveBeenCalledExactlyOnceWith(1);
  await act(async () => { pending.reject(null); await first; });
  expect(result.current.actionError).toBe('Failed to delete request');
  expect(gateway.list).toHaveBeenCalledOnce();
  await act(() => result.current.remove(1));
  await waitFor(() => expect(gateway.list).toHaveBeenCalledTimes(2));
});

it('does not resend a confirmed reply when refreshing its server state fails', async () => {
  const gateway: SupportSessionPort = {
    read: vi.fn().mockRejectedValueOnce(null).mockRejectedValueOnce(new Error('Still offline')).mockResolvedValue(supportRequest({ status: 'InProgress', replyCount: 1, replies: [supportReply({ isFromAdmin: true })] })),
    reply: vi.fn().mockResolvedValue(supportReply({ isFromAdmin: true })), remove: vi.fn(),
  };
  const { result } = renderHook(() => useSupportConversation(supportRequest(), gateway, vi.fn()));
  act(() => result.current.setReplyText('Answer'));
  await act(() => result.current.sendReply());
  expect(result.current.replyText).toBe('');
  expect(result.current.request.replyCount).toBe(1);
  expect(result.current.request.replies).toHaveLength(1);
  expect(result.current.refreshError).toBe('Failed to refresh request');
  expect(result.current.error).toBeNull();
  await act(() => result.current.refresh());
  expect(result.current.error).toBe('Still offline');
  await act(() => result.current.refresh());
  expect(result.current.refreshError).toBeNull();
  expect(result.current.request.status).toBe('InProgress');
  expect(gateway.reply).toHaveBeenCalledOnce();
  expect(gateway.read).toHaveBeenCalledTimes(3);
});
