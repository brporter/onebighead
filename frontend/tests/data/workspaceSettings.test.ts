import { act, renderHook, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useWorkspaceSettings } from '../../src/data/workspaces/useWorkspaceSettings';
import { removeWorkspace } from '../../src/data/workspaces/removeWorkspace';
import { deferred } from '../testUtils/deferred';
import type { RestorableWorkspace } from '../../src/api/workspaces';
import { SessionChanges } from '../../src/data/auth/SessionChanges';

function session() { return { changes: new SessionChanges(), refresh: vi.fn().mockResolvedValue(undefined), confirmDiscard: vi.fn().mockReturnValue(true) }; }

function port() {
  return { getRestorableWorkspaces: vi.fn().mockResolvedValue([]), switch: vi.fn().mockResolvedValue({ success: true }), leave: vi.fn().mockResolvedValue({ success: true }), restoreWorkspace: vi.fn().mockResolvedValue({ workspaceId: 2, name: 'Library' }) };
}

it('retries failed recovery reads and aborts a replaced or unmounted request', async () => {
  const pending = deferred<RestorableWorkspace[]>();
  const gateway = port();
  gateway.getRestorableWorkspaces.mockRejectedValueOnce(new Error('Offline')).mockReturnValueOnce(pending.promise);
  const { result, unmount } = renderHook(() => useWorkspaceSettings(gateway, session()));
  await waitFor(() => expect(result.current.deleted.error).toBe('Offline'));
  const firstSignal = gateway.getRestorableWorkspaces.mock.calls[0][0].signal;
  act(() => result.current.deleted.retry());
  expect(firstSignal.aborted).toBe(true);
  expect(result.current.deleted.loading).toBe(true);
  const retrySignal = gateway.getRestorableWorkspaces.mock.calls[1][0].signal;
  unmount();
  expect(retrySignal.aborted).toBe(true);
  await act(async () => pending.resolve([]));
});

it('serializes workspace changes and refreshes identity and availability after every outcome', async () => {
  const gateway = port();
  const current = session();
  const pending = deferred<{ success: boolean }>();
  gateway.switch.mockReturnValueOnce(pending.promise);
  const { result } = renderHook(() => useWorkspaceSettings(gateway, current));
  await waitFor(() => expect(result.current.deleted.loading).toBe(false));
  act(() => { void result.current.switchTo(2); void result.current.leave(3); });
  expect(gateway.leave).not.toHaveBeenCalled();
  expect(result.current.pending).toBe(true);
  await act(async () => pending.resolve({ success: false }));
  expect(result.current.error).toBe('Failed to switch workspace');
  expect(current.refresh).toHaveBeenCalledOnce();
  await act(async () => { await result.current.switchTo(2); });
  gateway.leave.mockResolvedValueOnce({ success: false });
  await act(async () => { await result.current.leave(3); });
  expect(result.current.error).toBe('Failed to leave workspace');
  await act(async () => { await result.current.leave(3); await result.current.restore(4); });
  expect(gateway.restoreWorkspace).toHaveBeenCalledWith(4);
  expect(current.refresh).toHaveBeenCalledTimes(5);
  await waitFor(() => expect(gateway.getRestorableWorkspaces).toHaveBeenCalledTimes(5));
});

it('retains restore failures and finishes authoritative session recovery even after unmount', async () => {
  const gateway = port();
  const pending = deferred<unknown>();
  gateway.restoreWorkspace.mockRejectedValueOnce(null).mockReturnValueOnce(pending.promise);
  const current = session();
  const { result, unmount } = renderHook(() => useWorkspaceSettings(gateway, current));
  await act(async () => { await result.current.restore(4); });
  expect(result.current.error).toBe('Failed to restore workspace');
  act(() => { void result.current.restore(4); });
  unmount();
  await act(async () => pending.resolve({ workspaceId: 4, name: 'Library' }));
  expect(current.refresh).toHaveBeenCalledTimes(2);
  expect(current.changes.getSnapshot().pending).toBe(false);
});

it('honors other editors before changing session and never replays a write during recovery', async () => {
  const gateway = port();
  const current = session();
  current.confirmDiscard.mockReturnValue(false);
  const release = current.changes.protect({ dirty: true, pending: false });
  const { result } = renderHook(() => useWorkspaceSettings(gateway, current));
  await act(async () => { await result.current.switchTo(2); });
  expect(result.current.error).toBe('Workspace change cancelled');
  expect(gateway.switch).not.toHaveBeenCalled();
  expect(current.refresh).not.toHaveBeenCalled();
  release();
  gateway.restoreWorkspace.mockRejectedValueOnce(new Error('Response lost'));
  current.refresh.mockRejectedValueOnce(new Error('Read offline')).mockResolvedValue(undefined);
  await act(async () => { await result.current.restore(4); });
  expect(result.current.error).toBe('Review your workspaces before trying again.');
  expect(current.changes.getSnapshot().recovery).toBe(true);
  await act(async () => { await result.current.leave(2); });
  expect(gateway.leave).not.toHaveBeenCalled();
  await act(async () => { await current.changes.retryRefresh(); });
  expect(current.changes.getSnapshot().recovery).toBe(false);
  expect(current.refresh).toHaveBeenCalledTimes(2);
  expect(gateway.restoreWorkspace).toHaveBeenCalledExactlyOnceWith(4);
});

it('validates deletion and reports the resulting session transition', async () => {
  const current = session();
  const gateway = { deleteWorkspace: vi.fn().mockResolvedValueOnce({ success: false }).mockResolvedValueOnce({ success: true }).mockResolvedValue({ success: true, userSoftDeleted: true }) };
  await expect(removeWorkspace(2, gateway, current)).rejects.toThrow('Failed to delete workspace');
  await expect(removeWorkspace(2, gateway, current)).resolves.toBe('changed');
  await expect(removeWorkspace(2, gateway, current)).resolves.toBe('signed-out');
  await expect(removeWorkspace(3, gateway, current)).resolves.toBe('signed-out');
  expect(gateway.deleteWorkspace).toHaveBeenCalledTimes(4);
  expect(current.refresh).toHaveBeenCalledTimes(4);
});

it('honors unsaved work before deletion and recovers uncertain writes using reads only', async () => {
  const current = session();
  const gateway = { deleteWorkspace: vi.fn().mockRejectedValue(new Error('Response lost')) };
  const release = current.changes.protect({ dirty: true, pending: false });
  current.confirmDiscard.mockReturnValue(false);
  await expect(removeWorkspace(1, gateway, current)).rejects.toThrow('Workspace deletion cancelled');
  expect(gateway.deleteWorkspace).not.toHaveBeenCalled();
  release();
  current.refresh.mockRejectedValueOnce(new Error('Session offline'));
  await expect(removeWorkspace(1, gateway, current)).rejects.toThrow('Review deletion information before trying again.');
  expect(current.changes.getSnapshot().recovery).toBe(true);
  await current.changes.retryRefresh();
  expect(current.changes.getSnapshot().error).toBe('Response lost');
  expect(current.changes.getSnapshot().recovery).toBe(false);
  expect(current.refresh).toHaveBeenCalledTimes(2);
  expect(gateway.deleteWorkspace).toHaveBeenCalledOnce();
});
