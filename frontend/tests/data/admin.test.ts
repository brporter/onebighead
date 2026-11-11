import { act, renderHook, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useAdminUsers } from '../../src/data/admin/useAdminUsers';
import { useAdminWorkspaces } from '../../src/data/admin/useAdminWorkspaces';
import { useAdminTemplates } from '../../src/data/admin/useAdminTemplates';
import { useSystemTemplateDefinition } from '../../src/data/admin/useSystemTemplateDefinition';
import { createMockItemTemplate } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';
import type { UserSummary, ItemTemplate } from '../../src/utils/types';

const user: UserSummary = { userId: 1, email: 'first@example.com', workspaceId: 1, workspaceName: 'Library', identityProvider: 'Google', isSystemAdministrator: false, createdAt: '2026-01-01' };

it('keeps the latest user search and refreshes that search when an earlier mutation completes', async () => {
  const stale = deferred<UserSummary[]>();
  const removal = deferred<void>();
  const gateway = { getUsers: vi.fn().mockReturnValueOnce(stale.promise).mockResolvedValue([user]), deleteUser: vi.fn().mockReturnValue(removal.promise), setAdminStatus: vi.fn().mockResolvedValue({ ...user, isSystemAdministrator: true }) };
  const { result, rerender } = renderHook(({ query }) => useAdminUsers(query, gateway), { initialProps: { query: '' } });
  expect(gateway.getUsers).toHaveBeenLastCalledWith(undefined, { signal: expect.any(AbortSignal) });
  const signal = gateway.getUsers.mock.calls[0][1].signal;
  rerender({ query: ' first ' });
  expect(signal.aborted).toBe(true);
  await waitFor(() => expect(result.current.data).toEqual([user]));
  await act(async () => stale.resolve([]));
  expect(result.current.data).toEqual([user]);
  act(() => { void result.current.remove(1); void result.current.setAdministrator(1, true); });
  expect(gateway.setAdminStatus).not.toHaveBeenCalled();
  rerender({ query: 'second' });
  await act(async () => removal.resolve());
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(gateway.getUsers).toHaveBeenLastCalledWith('second', { signal: expect.any(AbortSignal) });
  await act(async () => { await result.current.setAdministrator(1, true); });
  expect(gateway.setAdminStatus).toHaveBeenCalledWith(1, true);
});

it('retains workspace errors for retry and skips revalidation after unmount', async () => {
  const pending = deferred<void>();
  const gateway = { getWorkspaces: vi.fn().mockRejectedValueOnce(new Error('Offline')).mockResolvedValue([]), deleteWorkspace: vi.fn().mockRejectedValueOnce(new Error('Denied')).mockReturnValue(pending.promise) };
  const { result, unmount } = renderHook(() => useAdminWorkspaces(gateway));
  await waitFor(() => expect(result.current.error).toBe('Offline'));
  act(() => result.current.retry());
  await waitFor(() => expect(result.current.data).toEqual([]));
  await act(async () => { await result.current.remove(2); });
  expect(result.current.actionError).toBe('Denied');
  act(() => { void result.current.remove(2); });
  unmount();
  await act(async () => pending.resolve());
  expect(gateway.getWorkspaces).toHaveBeenCalledTimes(2);
});

it('revalidates the system library only after confirmed deletion', async () => {
  const template = createMockItemTemplate();
  const gateway = { getSystemTemplates: vi.fn().mockResolvedValueOnce([template]).mockResolvedValue([]), deleteSystemTemplate: vi.fn().mockRejectedValueOnce(null).mockResolvedValue(undefined) };
  const { result } = renderHook(() => useAdminTemplates(gateway));
  await waitFor(() => expect(result.current.data).toEqual([template]));
  await act(async () => { await result.current.remove(1); });
  expect(result.current.actionError).toBe('Unable to delete system template');
  expect(result.current.data).toEqual([template]);
  await act(async () => { await result.current.remove(1); });
  await waitFor(() => expect(result.current.data).toEqual([]));
});

it('keeps a failed system draft, validates fields and permits a single pending creation', async () => {
  const pending = deferred<ItemTemplate>();
  const commands = { createSystemTemplate: vi.fn().mockRejectedValueOnce(new Error('Offline')).mockReturnValue(pending.promise), updateSystemTemplate: vi.fn() };
  const saved = vi.fn();
  const { result } = renderHook(() => useSystemTemplateDefinition(null, commands, saved));
  await act(async () => { await result.current.save(); });
  expect(result.current.error).toBe('Name is required');
  expect(commands.createSystemTemplate).not.toHaveBeenCalled();
  act(() => result.current.setDraft(draft => ({ ...draft, name: ' Books ' })));
  await act(async () => { await result.current.save(); });
  expect(result.current.error).toBe('Offline');
  expect(result.current.dirty).toBe(true);
  act(() => { void result.current.save(); void result.current.save(); });
  expect(commands.createSystemTemplate).toHaveBeenCalledTimes(2);
  expect(result.current.saving).toBe(true);
  await act(async () => pending.resolve(createMockItemTemplate()));
  expect(saved).toHaveBeenCalledOnce();
  expect(commands.createSystemTemplate).toHaveBeenLastCalledWith({ name: 'Books', description: '', properties: [] });
});

it('updates system templates in place and ignores a completion after the session ends', async () => {
  const template = createMockItemTemplate({ isSystem: true });
  const pending = deferred<ItemTemplate>();
  const commands = { createSystemTemplate: vi.fn(), updateSystemTemplate: vi.fn().mockReturnValue(pending.promise) };
  const saved = vi.fn();
  const { result, unmount } = renderHook(() => useSystemTemplateDefinition(template, commands, saved));
  expect(result.current.dirty).toBe(false);
  act(() => { void result.current.save(); });
  expect(commands.updateSystemTemplate).toHaveBeenCalledWith(template.itemTemplateId, expect.objectContaining({ name: template.name }));
  unmount();
  await act(async () => pending.resolve(template));
  expect(saved).not.toHaveBeenCalled();
});
