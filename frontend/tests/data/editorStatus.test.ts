import { act, renderHook } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useEditorStatus } from '../../src/data/shared/useEditorStatus';
import { useSectionStatus } from '../../src/data/settings/useSectionStatus';

it('reports changes and releases constraints when a workflow unmounts or changes listeners', () => {
  const first = vi.fn();
  const second = vi.fn();
  const { rerender, unmount } = renderHook(({ dirty, pending, listener }) => useEditorStatus(dirty, pending, listener), { initialProps: { dirty: true, pending: false, listener: first } });
  expect(first).toHaveBeenLastCalledWith({ dirty: true, pending: false });
  rerender({ dirty: true, pending: true, listener: first });
  expect(first).toHaveBeenLastCalledWith({ dirty: true, pending: true });
  rerender({ dirty: false, pending: true, listener: second });
  expect(first).toHaveBeenLastCalledWith({ dirty: false, pending: false });
  expect(second).toHaveBeenLastCalledWith({ dirty: false, pending: true });
  unmount();
  expect(second).toHaveBeenLastCalledWith({ dirty: false, pending: false });
  renderHook(() => useEditorStatus(false, false)).unmount();
});

it('resets the active section and ignores callbacks from a previous editor', () => {
  const { result, rerender } = renderHook(({ section }) => useSectionStatus(section), { initialProps: { section: 'collections' } });
  const old = result.current;
  act(() => old.report({ dirty: true, pending: true }));
  expect(result.current).toMatchObject({ dirty: true, pending: true });
  rerender({ section: 'templates' });
  expect(result.current).toMatchObject({ dirty: false, pending: false });
  act(() => result.current.report({ dirty: true, pending: false }));
  act(() => old.report({ dirty: false, pending: true }));
  expect(result.current).toMatchObject({ dirty: true, pending: false });
});
