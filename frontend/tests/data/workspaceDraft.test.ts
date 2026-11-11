import { act, renderHook } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useWorkspaceDraft } from '../../src/data/workspaces/useWorkspaceDraft';
import { WorkspaceRole, type WorkspaceMembership } from '../../src/utils/types';
import { deferred } from '../testUtils/deferred';

const workspace: WorkspaceMembership = { workspaceId: 1, workspaceName: 'Library', slug: 'library', workspaceRole: WorkspaceRole.WorkspaceAdmin, hasCompletedWelcome: true };

it('validates and normalizes workspace drafts without sending invalid requests', async () => {
  const save = vi.fn().mockResolvedValue(undefined);
  const saved = vi.fn();
  const { result } = renderHook(() => useWorkspaceDraft(workspace, save, async () => {}, saved));
  expect(result.current.dirty).toBe(false);
  act(() => result.current.setDraft({ name: ' ', slug: 'library' }));
  await act(() => result.current.save());
  expect(result.current.error).toBe('Workspace name is required');
  act(() => result.current.setDraft({ name: 'Library', slug: 'invalid--slug' }));
  expect(result.current.dirty).toBe(true);
  await act(() => result.current.save());
  expect(result.current.error).toContain('no consecutive hyphens');
  expect(save).not.toHaveBeenCalled();
  act(() => result.current.setDraft({ name: ' Updated ', slug: ' new-library ' }));
  await act(() => result.current.save());
  expect(save).toHaveBeenLastCalledWith(1, { name: 'Updated', slug: 'new-library' });
  expect(saved).toHaveBeenCalledOnce();
  act(() => result.current.setDraft({ name: 'Updated', slug: ' ' }));
  await act(() => result.current.save());
  expect(save).toHaveBeenLastCalledWith(1, { name: 'Updated', slug: null });
});

it('suggests a missing slug, retains drafts through refreshed props and serializes retryable saves', async () => {
  const pending = deferred<void>();
  const save = vi.fn().mockReturnValueOnce(pending.promise).mockResolvedValue(undefined);
  const saved = vi.fn();
  const { result, rerender } = renderHook(({ value }) => useWorkspaceDraft(value, save, async () => {}, saved), { initialProps: { value: { ...workspace, slug: null } } });
  expect(result.current.draft).toEqual({ name: 'Library', slug: 'library' });
  act(() => result.current.setDraft({ name: 'Edited', slug: 'edited' }));
  rerender({ value: { ...workspace, workspaceName: 'Refreshed', slug: null } });
  expect(result.current.draft.name).toBe('Edited');
  let saving!: Promise<void>;
  act(() => { saving = result.current.save(); void result.current.save(); });
  expect(save).toHaveBeenCalledOnce();
  expect(result.current.pending).toBe(true);
  await act(async () => { pending.reject(null); await saving; });
  expect(result.current.error).toBe('Failed to save workspace');
  expect(result.current.draft).toEqual({ name: 'Edited', slug: 'edited' });
  expect(saved).not.toHaveBeenCalled();
  await act(() => result.current.save());
  expect(result.current.error).toBeNull();
  expect(saved).toHaveBeenCalledOnce();
});

it('does not complete a replacement editor when an unmounted save finishes', async () => {
  const pending = deferred<void>();
  const saved = vi.fn();
  const { result, unmount } = renderHook(() => useWorkspaceDraft(workspace, () => pending.promise, async () => {}, saved));
  let saving!: Promise<void>;
  act(() => { saving = result.current.save(); });
  unmount();
  await act(async () => { pending.resolve(); await saving; });
  expect(saved).not.toHaveBeenCalled();
});

it.each([true, false])('retries only the session read after an interrupted refresh (write confirmed: %s)', async confirmed => {
  const read = deferred<void>();
  const save = confirmed ? vi.fn().mockResolvedValue(undefined) : vi.fn().mockRejectedValue(new Error('Response lost'));
  const refresh = vi.fn().mockRejectedValueOnce(null).mockReturnValueOnce(read.promise);
  const saved = vi.fn();
  const { result } = renderHook(() => useWorkspaceDraft(workspace, save, refresh, saved));
  act(() => result.current.setDraft({ name: ' New library ', slug: 'new-library' }));
  await act(() => result.current.save());
  expect(result.current.error).toBe('Unable to refresh workspace details');
  expect(result.current.reviewRequired).toBe(true);
  expect(saved).not.toHaveBeenCalled();
  let recovering!: Promise<void>;
  act(() => { recovering = result.current.save(); void result.current.save(); });
  expect(result.current.pending).toBe(true);
  expect(save).toHaveBeenCalledOnce();
  expect(refresh).toHaveBeenCalledTimes(2);
  await act(async () => { read.resolve(); await recovering; });
  expect(result.current.reviewRequired).toBe(false);
  expect(result.current.pending).toBe(false);
  if (confirmed) {
    expect(result.current.error).toBeNull();
    expect(result.current.dirty).toBe(false);
    expect(result.current.draft.name).toBe('New library');
    expect(saved).toHaveBeenCalledOnce();
  } else {
    expect(result.current.error).toBe('Response lost');
    expect(result.current.dirty).toBe(true);
    expect(result.current.draft.name).toBe(' New library ');
    expect(saved).not.toHaveBeenCalled();
  }
});

it('finishes the authoritative refresh after unmount without calling a retired editor', async () => {
  const read = deferred<void>();
  const refresh = vi.fn().mockReturnValue(read.promise);
  const saved = vi.fn();
  const { result, unmount } = renderHook(() => useWorkspaceDraft(workspace, async () => {}, refresh, saved));
  let saving!: Promise<void>;
  await act(async () => { saving = result.current.save(); });
  expect(refresh).toHaveBeenCalledOnce();
  unmount();
  await act(async () => { read.resolve(); await saving; });
  expect(saved).not.toHaveBeenCalled();
});
