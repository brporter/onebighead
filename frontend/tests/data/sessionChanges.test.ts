import { expect, it, vi } from 'vitest';
import { SessionChanges } from '../../src/data/auth/SessionChanges';
import { deferred } from '../testUtils/deferred';

it('checks all mounted editors before changing the session and releases removed protections', async () => {
  const changes = new SessionChanges();
  const change = vi.fn();
  const refresh = vi.fn();
  const confirm = vi.fn().mockReturnValue(false);
  const releaseDirty = changes.protect({ dirty: true, pending: false });
  const releasePending = changes.protect({ dirty: false, pending: true });
  expect(await changes.run('workspace', change, refresh, confirm)).toBe(false);
  expect(changes.getSnapshot().error).toContain('Wait for the current action');
  expect(confirm).not.toHaveBeenCalled();
  releasePending();
  expect(await changes.run('workspace', change, refresh, confirm)).toBe(false);
  expect(confirm).toHaveBeenCalledOnce();
  expect(change).not.toHaveBeenCalled();
  releaseDirty();
  expect(await changes.run('workspace', change, refresh, confirm)).toBe(true);
  expect(change).toHaveBeenCalledOnce();
  expect(refresh).toHaveBeenCalledOnce();
  expect(changes.getSnapshot()).toMatchObject({ pending: false, recovery: false, error: null });
});

it('confirms once for multiple drafts and serializes different session actions through reconciliation', async () => {
  const changes = new SessionChanges();
  changes.protect({ dirty: true, pending: false });
  changes.protect({ dirty: true, pending: false });
  const write = deferred<void>();
  const read = deferred<void>();
  const change = vi.fn().mockReturnValue(write.promise);
  const refresh = vi.fn().mockReturnValue(read.promise);
  const confirm = vi.fn().mockReturnValue(true);
  const operation = changes.run('workspace', change, refresh, confirm);
  expect(confirm).toHaveBeenCalledOnce();
  expect(await changes.run('logout', change, refresh, confirm)).toBe(false);
  write.resolve();
  await Promise.resolve();
  expect(refresh).toHaveBeenCalledOnce();
  expect(changes.getSnapshot().pending).toBe(true);
  expect(await changes.retryRefresh()).toBe(false);
  expect(await changes.run('workspace', change, refresh, confirm)).toBe(false);
  read.resolve();
  expect(await operation).toBe(true);
  expect(change).toHaveBeenCalledOnce();
});

it('reconciles even a failed write and exposes its error after confirming the session', async () => {
  const changes = new SessionChanges();
  const refresh = vi.fn();
  expect(await changes.run('workspace', vi.fn().mockRejectedValue(new Error('Switch denied')), refresh, vi.fn())).toBe(false);
  expect(refresh).toHaveBeenCalledOnce();
  expect(changes.getSnapshot()).toMatchObject({ pending: false, recovery: false, error: 'Switch denied' });
});

it.each(['workspace', 'logout', 'account', 'account-deletion'] as const)('retains a failed %s action through read-only recovery without sending the write again', async kind => {
  const changes = new SessionChanges();
  const change = vi.fn().mockRejectedValue(null);
  const refresh = vi.fn().mockRejectedValueOnce(null).mockRejectedValueOnce(new Error('Still offline')).mockResolvedValue(undefined);
  expect(await changes.run(kind, change, refresh, vi.fn())).toBe(false);
  expect(changes.getSnapshot()).toMatchObject({ pending: false, recovery: true, error: 'Unable to refresh your session' });
  expect(await changes.run(kind, change, refresh, vi.fn())).toBe(false);
  expect(await changes.retryRefresh()).toBe(false);
  expect(changes.getSnapshot().error).toBe('Still offline');
  expect(await changes.retryRefresh()).toBe(false);
  expect(changes.getSnapshot()).toMatchObject({ recovery: false, error: { workspace: 'Unable to switch workspace', logout: 'Unable to sign out', account: 'Unable to update account', 'account-deletion': 'Unable to delete account' }[kind] });
  expect(change).toHaveBeenCalledOnce();
  expect(refresh).toHaveBeenCalledTimes(3);
  expect(await changes.retryRefresh()).toBe(false);
});

it('recovers a confirmed switch with only a fresh session read', async () => {
  const changes = new SessionChanges();
  const change = vi.fn();
  const refresh = vi.fn().mockRejectedValueOnce(new Error('Read failed')).mockResolvedValue(undefined);
  await changes.run('workspace', change, refresh, vi.fn());
  expect(changes.getSnapshot().recovery).toBe(true);
  expect(await changes.retryRefresh()).toBe(true);
  expect(changes.getSnapshot()).toMatchObject({ recovery: false, error: null });
  expect(change).toHaveBeenCalledOnce();
});

it.each(['logout', 'account-deletion'] as const)('allows successful %s to unload, does not refresh a signed-out session and rejects subsequent writes', async kind => {
  const changes = new SessionChanges();
  const refresh = vi.fn();
  expect(await changes.run(kind, vi.fn(), refresh, vi.fn())).toBe(true);
  expect(changes.getSnapshot()).toMatchObject({ leaving: true, pending: false });
  expect(refresh).not.toHaveBeenCalled();
  expect(await changes.run('workspace', vi.fn(), refresh, vi.fn())).toBe(false);
});

it('publishes stable snapshots and releases subscribers', async () => {
  const changes = new SessionChanges();
  const initial = changes.getSnapshot();
  expect(changes.getSnapshot()).toBe(initial);
  const listener = vi.fn();
  const stop = changes.subscribe(listener);
  await changes.run('workspace', vi.fn(), vi.fn(), vi.fn());
  expect(listener).toHaveBeenCalled();
  expect(changes.getSnapshot()).not.toBe(initial);
  stop();
  listener.mockClear();
  await changes.run('workspace', vi.fn(), vi.fn(), vi.fn());
  expect(listener).not.toHaveBeenCalled();
});

it('keeps feedback with its initiating control through recovery and clears ownership on the next action', async () => {
  const changes = new SessionChanges();
  const header = Symbol('header');
  const settings = Symbol('settings');
  const write = vi.fn().mockRejectedValue(new Error('Response lost'));
  const refresh = vi.fn().mockRejectedValueOnce(new Error('Read failed')).mockResolvedValue(undefined);
  await changes.run('workspace', write, refresh, vi.fn(), header);
  expect(changes.getSnapshot()).toMatchObject({ source: header, recovery: true });
  await changes.run('workspace', vi.fn(), vi.fn(), vi.fn(), settings);
  expect(changes.getSnapshot().source).toBe(header);
  await changes.retryRefresh();
  expect(changes.getSnapshot()).toMatchObject({ source: header, recovery: false, error: 'Response lost' });
  expect(write).toHaveBeenCalledOnce();
  const release = changes.protect({ dirty: false, pending: true });
  await changes.run('workspace', vi.fn(), vi.fn(), vi.fn(), settings);
  expect(changes.getSnapshot().source).toBe(settings);
  release();
  const releaseDraft = changes.protect({ dirty: true, pending: false });
  await changes.run('workspace', vi.fn(), vi.fn(), () => false, header);
  expect(changes.getSnapshot()).toMatchObject({ source: header, error: null });
  releaseDraft();
  await changes.run('workspace', vi.fn(), vi.fn(), vi.fn());
  expect(changes.getSnapshot().source).toBeUndefined();
});
