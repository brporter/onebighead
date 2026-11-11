import { act, renderHook } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useTemplateAssignments } from '../../src/data/templates/useTemplateAssignments';
import { deferred } from '../testUtils/deferred';

function setup() {
  const port = { associateTemplateWithCollection: vi.fn().mockResolvedValue(undefined),
    disassociateTemplateFromCollection: vi.fn().mockResolvedValue(undefined) };
  return { port, ...renderHook(() => useTemplateAssignments(4, [1], port)) };
}

it('tracks selection differences and saves only changed associations', async () => {
  const { result, port } = setup();
  expect(result.current.dirty).toBe(false);
  act(() => result.current.select([2]));
  expect(result.current.dirty).toBe(true);
  await act(async () => result.current.save());
  expect(port.associateTemplateWithCollection).toHaveBeenCalledExactlyOnceWith(4, 2);
  expect(port.disassociateTemplateFromCollection).toHaveBeenCalledExactlyOnceWith(4, 1);
  expect(result.current.dirty).toBe(false);
  expect(result.current.selectedIds).toEqual([2]);
  await act(async () => result.current.save());
  expect(port.associateTemplateWithCollection).toHaveBeenCalledOnce();
});

it.each(['add', 'remove'])('retains successful operations and retries only a failed %s', async operation => {
  const { result, port } = setup();
  const failed = operation === 'add' ? port.associateTemplateWithCollection : port.disassociateTemplateFromCollection;
  const succeeded = operation === 'add' ? port.disassociateTemplateFromCollection : port.associateTemplateWithCollection;
  failed.mockRejectedValueOnce(new Error('Offline'));
  act(() => result.current.select([2]));
  await act(async () => result.current.save());
  expect(result.current.error).toBe('Offline');
  expect(result.current.dirty).toBe(true);
  expect(result.current.selectedIds).toEqual([2]);
  await act(async () => result.current.save());
  expect(failed).toHaveBeenCalledTimes(2);
  expect(succeeded).toHaveBeenCalledOnce();
  expect(result.current.error).toBeNull();
  expect(result.current.dirty).toBe(false);
});

it('waits for all operations after an early failure and prevents duplicate saves', async () => {
  const { result, port } = setup();
  const pending = deferred<void>();
  port.associateTemplateWithCollection.mockRejectedValueOnce('Unknown failure');
  port.disassociateTemplateFromCollection.mockReturnValueOnce(pending.promise);
  act(() => result.current.select([2]));
  let save!: Promise<void>;
  await act(async () => { save = result.current.save(); });
  await act(async () => result.current.save());
  expect(result.current.saving).toBe(true);
  expect(port.associateTemplateWithCollection).toHaveBeenCalledOnce();
  await act(async () => { pending.resolve(); await save; });
  expect(result.current.error).toBe('Failed to save changes');
  expect(result.current.saving).toBe(false);
});

it('ignores late completion after the collection editor unmounts', async () => {
  const { result, port, unmount } = setup();
  const pending = deferred<void>();
  port.associateTemplateWithCollection.mockReturnValue(pending.promise);
  act(() => result.current.select([1, 2]));
  let save!: Promise<void>;
  act(() => { save = result.current.save(); });
  unmount();
  await act(async () => { pending.resolve(); await save; });
  expect(result.current.dirty).toBe(true);
});
