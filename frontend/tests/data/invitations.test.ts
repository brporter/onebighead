import { act, renderHook, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useTeamInvitations } from '../../src/data/invitations/useTeamInvitations';
import { readInvitationLink } from '../../src/data/invitations/invitationLink';
import { WorkspaceRole } from '../../src/utils/types';
import { createdInvitation, invitation } from '../testUtils/team';
import { deferred } from '../testUtils/deferred';

const gateway = () => ({ getInvitations: vi.fn().mockResolvedValue([]), inviteUser: vi.fn().mockResolvedValue(createdInvitation()), cancelInvitation: vi.fn().mockResolvedValue(undefined) });

it('captures only complete private links and preserves their token through sign-in without a request URL', () => {
  const values = new Map<string, string>();
  const storage = { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => { values.set(key, value); } };
  const { invitation: item, token } = createdInvitation();
  expect(readInvitationLink('bad-id', '#' + token, storage)).toBeNull();
  expect(readInvitationLink(item.invitationId, '', storage)).toBeNull();
  expect(readInvitationLink(item.invitationId, '#short', storage)).toBeNull();
  expect(readInvitationLink(item.invitationId, '#' + token, storage)).toEqual({ invitationId: item.invitationId, token });
  expect(readInvitationLink(item.invitationId, '', storage)).toEqual({ invitationId: item.invitationId, token });
});

it('requires a loaded invitation list and reports initial read failure', async () => {
  const read = deferred<ReturnType<typeof invitation>[]>();
  const api = gateway(); api.getInvitations.mockReturnValue(read.promise);
  const { result } = renderHook(() => useTeamInvitations(api));
  await act(async () => { await result.current.invite(); });
  expect(result.current.error).toContain('Load invitations');
  expect(api.inviteUser).not.toHaveBeenCalled();
  await act(async () => read.reject(null));
  expect(result.current.loadError).toBe('Failed to load invitations');
});

it('retains confirmed links if refresh fails and never repeats their creation when refreshing', async () => {
  const api = gateway();
  api.getInvitations.mockResolvedValueOnce([]).mockRejectedValueOnce(new Error('Offline')).mockResolvedValue([invitation()]);
  const { result } = renderHook(() => useTeamInvitations(api));
  await waitFor(() => expect(result.current.invitations).toEqual([]));
  act(() => { result.current.setEmail(' new@example.com '); result.current.setRole(WorkspaceRole.WorkspaceAdmin); });
  expect(result.current.dirty).toBe(true);
  await act(async () => { await result.current.invite(); });
  expect(result.current.invitations).toEqual([invitation()]);
  expect(result.current.created).toEqual(createdInvitation());
  expect(result.current.email).toBe('');
  expect(result.current.role).toBe(WorkspaceRole.Normal);
  expect(result.current.dirty).toBe(false);
  expect(result.current.loadError).toBe('Offline');
  await act(async () => { await result.current.refresh(); });
  expect(api.inviteUser).toHaveBeenCalledExactlyOnceWith({ email: 'new@example.com', role: WorkspaceRole.WorkspaceAdmin });
});

it('replaces the displayed private link and clears it only when its invitation is cancelled', async () => {
  const api = gateway();
  const other = { ...invitation(), invitationId: 'b1234567-1234-1234-1234-123456789abc', email: 'other@example.com' };
  api.getInvitations.mockResolvedValueOnce([invitation(), other]).mockRejectedValue(new Error('Offline'));
  const { result } = renderHook(() => useTeamInvitations(api));
  await waitFor(() => expect(result.current.invitations).toHaveLength(2));
  await act(async () => { await result.current.renew(invitation()); });
  expect(result.current.invitations).toHaveLength(2);
  await act(async () => { await result.current.cancel(other.invitationId); });
  expect(result.current.created).toEqual(createdInvitation());
  await act(async () => { await result.current.cancel(invitation().invitationId); });
  expect(result.current.invitations).toEqual([]);
  expect(result.current.created).toBeNull();
  expect(result.current.message).toContain('cancelled');
});

it('can cancel a pending invitation whose private link has not been shown in this session', async () => {
  const api = gateway(); api.getInvitations.mockResolvedValueOnce([invitation()]).mockResolvedValue([]);
  const { result } = renderHook(() => useTeamInvitations(api));
  await waitFor(() => expect(result.current.invitations).toHaveLength(1));
  await act(async () => { await result.current.cancel(invitation().invitationId); });
  expect(result.current.created).toBeNull();
  expect(api.cancelInvitation).toHaveBeenCalledWith(invitation().invitationId);
});

it('keeps drafts on failure, reports unspecified errors and retires late results after unmount', async () => {
  const api = gateway(); api.inviteUser.mockRejectedValueOnce(null);
  const { result, unmount } = renderHook(() => useTeamInvitations(api));
  await waitFor(() => expect(result.current.invitations).toEqual([]));
  act(() => result.current.setEmail('new@example.com'));
  await act(async () => { await result.current.invite(); });
  expect(result.current.error).toBe('Failed to create invitation');
  expect(result.current.email).toBe('new@example.com');
  api.cancelInvitation.mockRejectedValueOnce(null);
  await act(async () => { await result.current.cancel(invitation().invitationId); });
  expect(result.current.error).toBe('Failed to cancel invitation');
  const write = deferred<ReturnType<typeof createdInvitation>>(); api.inviteUser.mockReturnValue(write.promise);
  let pending!: Promise<void>;
  act(() => { pending = result.current.invite(); });
  const signal = api.getInvitations.mock.calls[0][0].signal;
  unmount();
  await act(async () => { write.resolve(createdInvitation()); await pending; });
  expect(signal.aborted).toBe(true);
  expect(api.getInvitations).toHaveBeenCalledOnce();
});
