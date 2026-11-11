import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import AccountDeletionSection from '../src/components/user/AccountDeletionSection';
import { accountApi, DeletionBlockerReason, WorkspaceActionType, type UserDeletionInfo } from '../src/api/account';
import { WorkspaceRole } from '../src/utils/types';
import { useUser } from '../src/contexts/useUser';
import { createMockCurrentUser } from './testUtils';
import { deferred } from './testUtils/deferred';

vi.mock('../src/api/account', async importOriginal => ({
  ...await importOriginal<typeof import('../src/api/account')>(),
  accountApi: { getDeletionInfo: vi.fn(), deleteAccount: vi.fn() },
}));
vi.mock('../src/contexts/useUser', () => ({ useUser: vi.fn() }));
const logout = vi.fn();
const info: UserDeletionInfo = { userId: 1, email: 'test@example.com', workspaceMemberships: [], workspacesRequiringAction: 0, canDeleteImmediately: true };
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubGlobal('location', { href: '' });
  vi.mocked(useUser).mockReturnValue({ user: createMockCurrentUser(), loading: false, error: null, signedOut: false, refetch: vi.fn(), logout });
  vi.mocked(accountApi.getDeletionInfo).mockResolvedValue(info);
});

it('does not open confirmation for failed or pending account lookups and supports retry', async () => {
  const pending = deferred<UserDeletionInfo>();
  vi.mocked(accountApi.getDeletionInfo).mockRejectedValueOnce(null).mockReturnValueOnce(pending.promise);
  render(<AccountDeletionSection />);
  expect(screen.getByText(/Shared collections remain available to their other members/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Delete My Account' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Failed to load account information');
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Delete My Account' }));
  const loading = screen.getByRole('button', { name: 'Loading...' });
  expect(loading).toBeDisabled();
  fireEvent.click(loading);
  expect(accountApi.getDeletionInfo).toHaveBeenCalledTimes(2);
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  await act(async () => pending.resolve(info));
  expect(screen.getByRole('dialog', { name: 'Delete Your Account' })).toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('preserves a failed deletion and never treats an unspecified server failure as completion', async () => {
  vi.mocked(accountApi.deleteAccount).mockResolvedValue({ success: false });
  render(<AccountDeletionSection />);
  await confirmDeletion();
  expect(await screen.findByText('Failed to delete account')).toBeInTheDocument();
  expect(window.location.href).toBe('');
  expect(screen.getByRole('button', { name: 'Delete Account' })).toBeEnabled();
});

it('requires each workspace choice, submits transfers and deletion together, and resets confirmation on reopening', async () => {
  const membership = { workspaceName: 'Library', role: WorkspaceRole.WorkspaceAdmin, isOnlyUser: false, isOnlyAdmin: true, userCount: 2, canLeave: false, blockerReason: DeletionBlockerReason.SoleAdmin, otherUsers: [{ userId: 7, email: 'successor@example.com' }] };
  vi.mocked(accountApi.getDeletionInfo).mockResolvedValue({ ...info, workspacesRequiringAction: 2, canDeleteImmediately: false, workspaceMemberships: [
    { ...membership, workspaceId: 1, canLeave: true, blockerReason: DeletionBlockerReason.None },
    { ...membership, workspaceId: 2, workspaceName: 'Private library', isOnlyUser: true, blockerReason: DeletionBlockerReason.SoleUser },
    { ...membership, workspaceId: 3 },
  ] });
  vi.mocked(accountApi.deleteAccount).mockResolvedValue({ success: true });
  const onDeleted = vi.fn();
  render(<AccountDeletionSection onDeleted={onDeleted} />);
  fireEvent.click(screen.getByRole('button', { name: 'Delete My Account' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Confirm deletion of workspace' }));
  expect(screen.getByRole('button', { name: 'Delete Account' })).toBeDisabled();
  fireEvent.change(screen.getByRole('combobox'), { target: { value: '7' } });
  fireEvent.change(screen.getByPlaceholderText('test@example.com'), { target: { value: 'test@example.com' } });
  expect(screen.getByRole('button', { name: 'Delete Account' })).toBeEnabled();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Delete My Account' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Confirm deletion of workspace' }));
  fireEvent.change(screen.getByRole('combobox'), { target: { value: '7' } });
  expect(screen.getByPlaceholderText('test@example.com')).toHaveValue('');
  fireEvent.change(screen.getByPlaceholderText('test@example.com'), { target: { value: 'test@example.com' } });
  fireEvent.click(screen.getByRole('button', { name: 'Delete Account' }));
  await waitFor(() => expect(onDeleted).toHaveBeenCalledOnce());
  expect(accountApi.deleteAccount).toHaveBeenCalledExactlyOnceWith({ confirmEmail: 'test@example.com', workspaceActions: [
    { workspaceId: 2, action: WorkspaceActionType.Delete },
    { workspaceId: 3, action: WorkspaceActionType.Transfer, transferToUserId: 7 },
  ] });
});

async function confirmDeletion() {
  fireEvent.click(screen.getByRole('button', { name: 'Delete My Account' }));
  await screen.findByRole('dialog', { name: 'Delete Your Account' });
  fireEvent.change(screen.getByPlaceholderText('test@example.com'), { target: { value: 'test@example.com' } });
  fireEvent.click(screen.getByRole('button', { name: 'Delete Account' }));
}

it('explains how to resolve a workspace with no eligible administrator instead of offering an empty selector', async () => {
  vi.mocked(accountApi.getDeletionInfo).mockResolvedValue({ ...info, canDeleteImmediately: false, workspacesRequiringAction: 1, workspaceMemberships: [{
    workspaceId: 9, workspaceName: 'Archived team', role: WorkspaceRole.WorkspaceAdmin, isOnlyUser: false,
    isOnlyAdmin: true, userCount: 2, canLeave: false, blockerReason: DeletionBlockerReason.SoleAdmin, otherUsers: [],
  }] });
  render(<AccountDeletionSection />);
  fireEvent.click(screen.getByRole('button', { name: 'Delete My Account' }));
  await screen.findByRole('dialog', { name: 'Delete Your Account' });
  expect(screen.getByText(/No active member can receive the admin role/)).toBeVisible();
  expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Delete Account' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(accountApi.deleteAccount).not.toHaveBeenCalled();
});

it('redirects after confirmed deletion without requesting a redundant logout', async () => {
  vi.mocked(accountApi.deleteAccount).mockResolvedValue({ success: true });
  render(<AccountDeletionSection />);
  await confirmDeletion();
  await waitFor(() => expect(window.location.href).toBe('/'));
  expect(accountApi.deleteAccount).toHaveBeenCalledExactlyOnceWith({ confirmEmail: 'test@example.com', workspaceActions: [] });
  expect(logout).not.toHaveBeenCalled();
});

it('notifies its completion callback only after a successful deletion and retains failures for retry', async () => {
  const onDeleted = vi.fn();
  vi.mocked(accountApi.deleteAccount).mockResolvedValueOnce({ success: false, error: 'Workspace changed; please review' }).mockResolvedValueOnce({ success: true });
  render(<AccountDeletionSection onDeleted={onDeleted} />);
  await confirmDeletion();
  expect(await screen.findByText('Workspace changed; please review')).toBeInTheDocument();
  expect(onDeleted).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Delete Account' }));
  await waitFor(() => expect(onDeleted).toHaveBeenCalledOnce());
  expect(window.location.href).toBe('');
  expect(logout).not.toHaveBeenCalled();
});

it('reloads stale workspace choices after rejection without repeating deletion and clears the old confirmation', async () => {
  vi.mocked(accountApi.deleteAccount).mockResolvedValue({ success: false, error: 'Workspace membership changed' });
  const next = deferred<UserDeletionInfo>();
  vi.mocked(accountApi.getDeletionInfo).mockResolvedValueOnce(info).mockReturnValueOnce(next.promise);
  render(<AccountDeletionSection />);
  await confirmDeletion();
  fireEvent.click(await screen.findByRole('button', { name: 'Review workspace choices' }));
  expect(screen.getByRole('button', { name: 'Loading...' })).toBeDisabled();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(accountApi.deleteAccount).toHaveBeenCalledOnce();
  await act(async () => next.resolve({ ...info, email: 'updated@example.test' }));
  expect(screen.getByPlaceholderText('updated@example.test')).toHaveValue('');
  expect(screen.getByRole('button', { name: 'Delete Account' })).toBeDisabled();
  expect(accountApi.getDeletionInfo).toHaveBeenCalledTimes(2);
  expect(screen.queryByText('Workspace membership changed')).not.toBeInTheDocument();
});

it('shows standalone read-only session recovery and reports pending status until identity is confirmed', async () => {
  const refetch = vi.fn().mockRejectedValueOnce(new Error('Session offline')).mockResolvedValue(undefined);
  vi.mocked(useUser).mockReturnValue({ user: createMockCurrentUser(), loading: false, error: null, signedOut: false, refetch, logout });
  vi.mocked(accountApi.deleteAccount).mockRejectedValue(new Error('Response lost'));
  const onStatusChange = vi.fn();
  render(<AccountDeletionSection onStatusChange={onStatusChange} />);
  await confirmDeletion();
  const retry = await screen.findByRole('button', { name: 'Retry session refresh' });
  expect(onStatusChange).toHaveBeenLastCalledWith({ dirty: false, pending: true });
  expect(screen.getByRole('button', { name: 'Delete My Account' })).toBeDisabled();
  fireEvent.click(retry);
  await waitFor(() => expect(onStatusChange).toHaveBeenLastCalledWith({ dirty: false, pending: false }));
  expect(refetch).toHaveBeenCalledTimes(2);
  expect(refetch).toHaveBeenLastCalledWith({ throwOnError: true, endSessionIfAnonymous: true });
  expect(accountApi.deleteAccount).toHaveBeenCalledOnce();
  expect(logout).not.toHaveBeenCalled();
});
