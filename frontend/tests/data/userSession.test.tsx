import { StrictMode } from 'react';
import { act, renderHook, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useUserSession } from '../../src/data/auth/useUserSession';
import { createMockCurrentUser } from '../testUtils';
import { deferred } from '../testUtils/deferred';
import type { CurrentUser } from '../../src/utils/types';

const user = createMockCurrentUser();

it('cancels replaced reads and keeps the latest identity despite late successes and errors', async () => {
  const first = deferred<CurrentUser>();
  const second = deferred<CurrentUser>();
  const gateway = { getCurrentUser: vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise).mockResolvedValue(user), logout: vi.fn() };
  const { result } = renderHook(() => useUserSession(gateway));
  await waitFor(() => expect(gateway.getCurrentUser).toHaveBeenCalledOnce());
  const firstSignal = gateway.getCurrentUser.mock.calls[0][0].signal;
  act(() => { void result.current.refetch(); });
  const secondSignal = gateway.getCurrentUser.mock.calls[1][0].signal;
  await act(async () => { await result.current.refetch(); });
  expect(firstSignal.aborted).toBe(true);
  expect(secondSignal.aborted).toBe(true);
  await act(async () => { first.resolve({ ...user, email: 'old@example.com' }); second.reject(new Error('Old failure')); });
  expect(result.current.user).toEqual(user);
  expect(result.current.error).toBeNull();
});

it('retains a confirmed identity after a transient refresh failure and clears it for an anonymous response', async () => {
  const gateway = { getCurrentUser: vi.fn().mockResolvedValueOnce(user).mockRejectedValueOnce(new Error('Offline')).mockResolvedValue(null), logout: vi.fn() };
  const { result } = renderHook(() => useUserSession(gateway));
  await waitFor(() => expect(result.current.user).toEqual(user));
  await act(async () => { await result.current.refetch(); });
  expect(result.current.user).toEqual(user);
  expect(result.current.error).toBe('Offline');
  await act(async () => { await result.current.refetch(); });
  expect(result.current.user).toBeNull();
  expect(result.current.error).toBeNull();
  expect(result.current.signedOut).toBe(false);
});

it('ends an intentionally removed account only after a confirmed anonymous read and suppresses stale refreshes', async () => {
  const gateway = { getCurrentUser: vi.fn().mockResolvedValueOnce(user).mockRejectedValueOnce(new Error('Offline')).mockResolvedValue(null), logout: vi.fn() };
  const { result } = renderHook(() => useUserSession(gateway));
  await waitFor(() => expect(result.current.user).toEqual(user));
  const options = { throwOnError: true, endSessionIfAnonymous: true };
  await act(async () => { await expect(result.current.refetch(options)).rejects.toThrow('Offline'); });
  expect(result.current.user).toEqual(user);
  expect(result.current.signedOut).toBe(false);
  await act(async () => { await result.current.refetch(options); });
  expect(result.current.user).toBeNull();
  expect(result.current.signedOut).toBe(true);
  await act(async () => { await result.current.refetch(); await result.current.logout(); });
  expect(gateway.getCurrentUser).toHaveBeenCalledTimes(3);
  expect(gateway.logout).not.toHaveBeenCalled();
});

it('keeps a confirmed account usable when a failed account-ending action did not commit', async () => {
  const gateway = { getCurrentUser: vi.fn().mockResolvedValue(user), logout: vi.fn() };
  const { result } = renderHook(() => useUserSession(gateway));
  await waitFor(() => expect(result.current.user).toEqual(user));
  await act(async () => { await result.current.refetch({ endSessionIfAnonymous: true }); });
  expect(result.current.signedOut).toBe(false);
  expect(result.current.user).toEqual(user);
  await act(async () => { await result.current.refetch(); });
  expect(gateway.getCurrentUser).toHaveBeenCalledTimes(3);
});

it('shares a pending logout, blocks refreshes and prevents stale reads from restoring a signed-out session', async () => {
  const read = deferred<CurrentUser>();
  const exit = deferred<void>();
  const gateway = { getCurrentUser: vi.fn().mockReturnValue(read.promise), logout: vi.fn().mockReturnValue(exit.promise) };
  const { result } = renderHook(() => useUserSession(gateway));
  await waitFor(() => expect(gateway.getCurrentUser).toHaveBeenCalledOnce());
  let operation: Promise<void>;
  act(() => {
    operation = result.current.logout();
    expect(result.current.logout()).toBe(operation);
  });
  await act(async () => { await result.current.refetch(); });
  expect(gateway.getCurrentUser).toHaveBeenCalledOnce();
  await act(async () => { exit.resolve(); await operation; });
  expect(gateway.getCurrentUser.mock.calls[0][0].signal.aborted).toBe(true);
  await act(async () => { read.resolve(user); await result.current.refetch(); await result.current.logout(); });
  expect(result.current.user).toBeNull();
  expect(result.current.loading).toBe(false);
  expect(gateway.logout).toHaveBeenCalledOnce();
  expect(gateway.getCurrentUser).toHaveBeenCalledOnce();
});

it('releases a failed logout for retry and keeps the session usable', async () => {
  const gateway = { getCurrentUser: vi.fn().mockResolvedValue(user), logout: vi.fn().mockRejectedValueOnce(new Error('Offline')).mockResolvedValue(undefined) };
  const { result } = renderHook(() => useUserSession(gateway));
  await waitFor(() => expect(result.current.user).toEqual(user));
  await act(async () => { await expect(result.current.logout()).rejects.toThrow('Offline'); });
  expect(result.current.user).toEqual(user);
  await act(async () => { await result.current.refetch(); await result.current.logout(); });
  expect(gateway.getCurrentUser).toHaveBeenCalledTimes(2);
  expect(gateway.logout).toHaveBeenCalledTimes(2);
  expect(result.current.user).toBeNull();
});

it('resumes the initial session check when an immediate logout fails', async () => {
  const exit = deferred<void>();
  const gateway = { getCurrentUser: vi.fn().mockResolvedValue(user), logout: vi.fn().mockReturnValue(exit.promise) };
  const { result } = renderHook(() => useUserSession(gateway));
  const operation = result.current.logout();
  await waitFor(() => expect(gateway.logout).toHaveBeenCalledOnce());
  expect(gateway.getCurrentUser).not.toHaveBeenCalled();
  await act(async () => {
    exit.reject(new Error('Offline'));
    await expect(operation).rejects.toThrow('Offline');
  });
  expect(result.current.loading).toBe(false);
  expect(result.current.user).toEqual(user);
});

it('cancels reads and ignores late session changes after unmount', async () => {
  const read = deferred<CurrentUser>();
  const exit = deferred<void>();
  const gateway = { getCurrentUser: vi.fn().mockReturnValue(read.promise), logout: vi.fn().mockReturnValue(exit.promise) };
  const { result, unmount } = renderHook(() => useUserSession(gateway));
  await waitFor(() => expect(gateway.getCurrentUser).toHaveBeenCalledOnce());
  const previous = result.current;
  const operation = result.current.logout();
  unmount();
  expect(gateway.getCurrentUser.mock.calls[0][0].signal.aborted).toBe(true);
  await act(async () => { read.resolve(user); exit.resolve(); await operation; await previous.refetch(); });
  expect(result.current).toBe(previous);
  expect(gateway.getCurrentUser).toHaveBeenCalledOnce();
});

it('does not start reads for a disposed mount and starts only one read in Strict Mode', async () => {
  const gateway = { getCurrentUser: vi.fn().mockResolvedValue(user), logout: vi.fn().mockResolvedValue(undefined) };
  const first = renderHook(() => useUserSession(gateway));
  first.unmount();
  await act(async () => { await first.result.current.logout(); });
  expect(gateway.getCurrentUser).not.toHaveBeenCalled();
  const second = renderHook(() => useUserSession(gateway), { wrapper: StrictMode });
  await waitFor(() => expect(second.result.current.user).toEqual(user));
  expect(gateway.getCurrentUser).toHaveBeenCalledOnce();
});


it('propagates required refresh failures while preserving the confirmed user and supports retry', async () => {
  const gateway = { getCurrentUser: vi.fn().mockResolvedValueOnce(user).mockRejectedValueOnce(new Error('Refresh offline')).mockResolvedValue(user), logout: vi.fn() };
  const { result } = renderHook(() => useUserSession(gateway));
  await waitFor(() => expect(result.current.user).toEqual(user));
  await act(async () => { await expect(result.current.refetch({ throwOnError: true })).rejects.toThrow('Refresh offline'); });
  expect(result.current.user).toEqual(user);
  expect(result.current.error).toBe('Refresh offline');
  await act(async () => { await result.current.refetch({ throwOnError: true }); });
  expect(result.current.error).toBeNull();
});

it('rejects a required refresh replaced by a newer read instead of allowing stale continuation', async () => {
  const read = deferred<CurrentUser>();
  const gateway = { getCurrentUser: vi.fn().mockResolvedValueOnce(user).mockReturnValueOnce(read.promise).mockResolvedValue(user), logout: vi.fn() };
  const { result } = renderHook(() => useUserSession(gateway));
  await waitFor(() => expect(result.current.user).toEqual(user));
  let refresh: Promise<void>;
  act(() => { refresh = result.current.refetch({ throwOnError: true }); });
  await act(async () => { await result.current.refetch(); });
  await act(async () => { read.resolve(user); await expect(refresh).rejects.toThrow('Session refresh was interrupted'); });
  expect(result.current.error).toBeNull();
});

it('rejects required refreshes during logout, after logout, and after unmount', async () => {
  const exit = deferred<void>();
  const gateway = { getCurrentUser: vi.fn().mockResolvedValue(user), logout: vi.fn().mockReturnValue(exit.promise) };
  const { result, unmount } = renderHook(() => useUserSession(gateway));
  await waitFor(() => expect(result.current.user).toEqual(user));
  const operation = result.current.logout();
  await expect(result.current.refetch({ throwOnError: true })).rejects.toThrow('Session refresh is unavailable');
  await act(async () => { exit.resolve(); await operation; });
  await expect(result.current.refetch({ throwOnError: true })).rejects.toThrow('Session refresh is unavailable');
  unmount();
  await expect(result.current.refetch({ throwOnError: true })).rejects.toThrow('Session refresh is unavailable');
  expect(gateway.getCurrentUser).toHaveBeenCalledOnce();
});
