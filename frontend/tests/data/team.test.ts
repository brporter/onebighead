import { act, renderHook, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { WorkspaceRole } from '../../src/utils/types';
import { prepareInvitation, requireTeamEdit, teamEditRestriction, teamRemovalConfirmation, validateTeamRole } from '../../src/data/team/teamPolicy';
import { useTeamMembers } from '../../src/data/team/useTeamMembers';
import { team, teamMember } from '../testUtils/team';
import { deferred } from '../testUtils/deferred';

it('normalizes invitation labels and validates email format and roles', () => {
  expect(prepareInvitation(' Reader@example.com ', WorkspaceRole.Normal)).toEqual({ email: 'Reader@example.com', role: WorkspaceRole.Normal });
  expect(prepareInvitation('reader@example.com', WorkspaceRole.WorkspaceAdmin)).toEqual({ email: 'reader@example.com', role: WorkspaceRole.WorkspaceAdmin });
  for (const email of ['', '   ', 'missing-at.example.com', 'reader@localhost', 'x'.repeat(315) + '@a.com'])
    expect(() => prepareInvitation(email, WorkspaceRole.Normal)).toThrow('valid email');
  expect(prepareInvitation(' MEMBER@EXAMPLE.COM ', WorkspaceRole.Normal).email).toBe('MEMBER@EXAMPLE.COM');
  expect(() => validateTeamRole('Owner' as WorkspaceRole)).toThrow('valid team role');
});

it('applies the same edit restrictions to role changes and removals', () => {
  const users = team();
  expect(teamEditRestriction(users, users[0], 1)).toContain('your own role');
  expect(teamEditRestriction(users, users[0], 9)).toContain('last admin');
  expect(teamEditRestriction(users, users[1], 1)).toBeNull();
  const otherAdmin = teamMember({ userId: 4, workspaceRole: WorkspaceRole.WorkspaceAdmin });
  expect(teamEditRestriction([...users, otherAdmin], users[0], 9)).toBeNull();
  expect(requireTeamEdit(users, 2, 1)).toBe(users[1]);
  expect(() => requireTeamEdit(users, 77, 1)).toThrow('no longer in the team');
  expect(() => requireTeamEdit(users, 1, 1)).toThrow('your own role');
  expect(() => requireTeamEdit(users, 1, 9)).toThrow('last admin');
  expect(teamRemovalConfirmation(users[1])).toContain('lose access');
  expect(teamRemovalConfirmation(users[2])).toBe('Cancel the invitation for pending@example.com?');
});

it('does not mutate before the initial list is available and surfaces fallback read errors', async () => {
  const read = deferred<ReturnType<typeof team>>();
  const gateway = { getUsers: vi.fn().mockReturnValue(read.promise), inviteUser: vi.fn(), updateUserRole: vi.fn(), removeUser: vi.fn() };
  const { result } = renderHook(() => useTeamMembers(1, gateway));
  await act(async () => { await result.current.remove(2); });
  expect(result.current.error).toContain('Load the team');
  expect(gateway.inviteUser).not.toHaveBeenCalled();
  await act(async () => read.reject(null));
  expect(result.current.loadError).toBe('Failed to load team members');
});

it('serializes writes through post-write refresh and retains confirmed role/removal state on read failures', async () => {
  const refresh = deferred<ReturnType<typeof team>>();
  const gateway = { getUsers: vi.fn().mockResolvedValueOnce(team()).mockReturnValueOnce(refresh.promise).mockRejectedValue(new Error('Offline')),
    inviteUser: vi.fn(), updateUserRole: vi.fn().mockResolvedValue(undefined), removeUser: vi.fn().mockResolvedValue(undefined) };
  const { result } = renderHook(() => useTeamMembers(1, gateway));
  await waitFor(() => expect(result.current.users).toHaveLength(3));
  let update!: Promise<void>;
  await act(async () => { update = result.current.changeRole(2, WorkspaceRole.WorkspaceAdmin); });
  expect(result.current.pending).toBe(true);
  expect(result.current.users?.find(user => user.userId === 2)?.workspaceRole).toBe(WorkspaceRole.WorkspaceAdmin);
  await act(async () => { await result.current.remove(3); await result.current.refresh(); });
  expect(gateway.removeUser).not.toHaveBeenCalled();
  expect(gateway.getUsers).toHaveBeenCalledTimes(2);
  await act(async () => { refresh.reject(new Error('Offline')); await update; });
  expect(result.current.pending).toBe(false);
  await act(async () => { await result.current.remove(3); });
  expect(result.current.users?.map(user => user.userId)).toEqual([1, 2]);
  expect(result.current.loadError).toBe('Offline');
});

it.each(['role', 'remove'] as const)('preserves state when %s fails with an unspecified error', async operation => {
  const gateway = { getUsers: vi.fn().mockResolvedValue(team()), inviteUser: vi.fn().mockRejectedValue(null), updateUserRole: vi.fn().mockRejectedValue(null), removeUser: vi.fn().mockRejectedValue(null) };
  const { result } = renderHook(() => useTeamMembers(1, gateway));
  await waitFor(() => expect(result.current.users).toHaveLength(3));
  await act(async () => {
    if (operation === 'role') await result.current.changeRole(2, WorkspaceRole.WorkspaceAdmin);
    else await result.current.remove(3);
  });
  expect(result.current.error).toMatch(/^Failed to/);
  expect(result.current.users).toEqual(team());
  expect(gateway.getUsers).toHaveBeenCalledOnce();
});

it('rejects programmatic self edits, unknown targets and invalid roles before transport calls', async () => {
  const gateway = { getUsers: vi.fn().mockResolvedValue(team()), inviteUser: vi.fn(), updateUserRole: vi.fn(), removeUser: vi.fn() };
  const { result } = renderHook(() => useTeamMembers(1, gateway));
  await waitFor(() => expect(result.current.users).toHaveLength(3));
  await act(async () => { await result.current.changeRole(1, WorkspaceRole.Normal); });
  expect(result.current.error).toContain('your own role');
  await act(async () => { await result.current.changeRole(2, 'Owner' as WorkspaceRole); });
  expect(result.current.error).toContain('valid team role');
  await act(async () => { await result.current.remove(99); });
  expect(result.current.error).toContain('no longer');
  expect(gateway.updateUserRole).not.toHaveBeenCalled();
  expect(gateway.removeUser).not.toHaveBeenCalled();
});

it('cancels a read on unmount and never refreshes a retired workspace after its write completes', async () => {
  const write = deferred<void>();
  const gateway = { getUsers: vi.fn().mockResolvedValue(team()), inviteUser: vi.fn(), updateUserRole: vi.fn().mockReturnValue(write.promise), removeUser: vi.fn() };
  const { result, unmount } = renderHook(() => useTeamMembers(1, gateway));
  await waitFor(() => expect(result.current.users).toHaveLength(3));
  const signal = gateway.getUsers.mock.calls[0][0].signal;
  let update!: Promise<void>;
  act(() => { update = result.current.changeRole(2, WorkspaceRole.WorkspaceAdmin); });
  unmount();
  expect(signal.aborted).toBe(true);
  await act(async () => { write.resolve(); await update; });
  expect(gateway.getUsers).toHaveBeenCalledOnce();
});
