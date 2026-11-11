import { act, renderHook } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useAsyncAction } from '../src/utils/useAsyncAction';
import { deferred } from './testUtils/deferred';

it('allows one pending action and clears its error on a successful retry', async () => {
  const { result } = renderHook(useAsyncAction);
  const pending = deferred<void>();
  const duplicate = vi.fn();
  let request!: Promise<void>;
  act(() => { request = result.current.run(() => pending.promise, 'Failed'); });
  expect(result.current.pending).toBe(true);
  await act(async () => { await result.current.run(duplicate, 'Failed'); });
  expect(duplicate).not.toHaveBeenCalled();
  await act(async () => { pending.reject(new Error('Offline')); await request; });
  expect(result.current.error).toBe('Offline');
  expect(result.current.pending).toBe(false);
  await act(async () => { await result.current.run(duplicate, 'Failed'); });
  expect(duplicate).toHaveBeenCalledOnce();
  expect(result.current.error).toBeNull();
});

it('handles synchronous failures with a fallback message', async () => {
  const { result } = renderHook(useAsyncAction);
  await act(async () => { await result.current.run(() => { throw null; }, 'Unable to save'); });
  expect(result.current.error).toBe('Unable to save');
});

it.each(['success', 'failure'])('settles an action after unmount: %s', async outcome => {
  const { result, unmount } = renderHook(useAsyncAction);
  const pending = deferred<void>();
  let request!: Promise<void>;
  act(() => { request = result.current.run(() => pending.promise, 'Failed'); });
  unmount();
  await act(async () => {
    if (outcome === 'success') pending.resolve(); else pending.reject(new Error('Offline'));
    await request;
  });
  expect(result.current.error).toBeNull();
});

it('delivers the result only after a successful action while mounted', async () => {
  const { result, unmount } = renderHook(useAsyncAction);
  const onSuccess = vi.fn();
  await act(async () => { await result.current.run(() => Promise.resolve(7), 'Failed', onSuccess); });
  expect(onSuccess).toHaveBeenCalledWith(7);
  await act(async () => { await result.current.run(() => Promise.reject(new Error('Offline')), 'Failed', onSuccess); });
  expect(onSuccess).toHaveBeenCalledTimes(1);
  const pending = deferred<number>();
  let request!: Promise<void>;
  act(() => { request = result.current.run(() => pending.promise, 'Failed', onSuccess); });
  unmount();
  await act(async () => { pending.resolve(8); await request; });
  expect(onSuccess).toHaveBeenCalledTimes(1);
});


it('awaits successful asynchronous follow-up work before allowing another action', async () => {
  const followUp = deferred<void>();
  const duplicate = vi.fn();
  const { result } = renderHook(useAsyncAction);
  let request!: Promise<void>;
  await act(async () => { request = result.current.run(() => 1, 'Failed', () => followUp.promise); });
  expect(result.current.pending).toBe(true);
  await act(async () => { await result.current.run(duplicate, 'Failed'); });
  expect(duplicate).not.toHaveBeenCalled();
  await act(async () => { followUp.resolve(); await request; });
  expect(result.current.pending).toBe(false);
});
