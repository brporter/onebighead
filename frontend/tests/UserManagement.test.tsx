import { beforeEach, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import UserManagement from '../src/components/user/UserManagement';
import { useUser } from '../src/contexts/useUser';
import { usersApi } from '../src/api/users';
import { WorkspaceRole, type CurrentUser } from '../src/utils/types';
import { deferred } from './testUtils/deferred';
import { team, teamAdministrator, createdInvitation } from './testUtils/team';

vi.mock('../src/contexts/useUser', () => ({ useUser: vi.fn() }));
vi.mock('../src/api/users', () => ({ usersApi: { getUsers: vi.fn(), getInvitations: vi.fn(), cancelInvitation: vi.fn(), inviteUser: vi.fn(), updateUserRole: vi.fn(), removeUser: vi.fn() } }));
const api = vi.mocked(usersApi);
function identity(user: CurrentUser | null) {
  vi.mocked(useUser).mockReturnValue({ user, loading: false, error: null, signedOut: false, refetch: vi.fn(), logout: vi.fn() });
}
beforeEach(() => {
  vi.resetAllMocks();
  identity(teamAdministrator());
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  api.getUsers.mockResolvedValue(team());
  api.inviteUser.mockResolvedValue(createdInvitation());
  api.getInvitations.mockResolvedValue([]);
  api.cancelInvitation.mockResolvedValue(undefined);
  api.updateUserRole.mockResolvedValue(undefined);
  api.removeUser.mockResolvedValue(undefined);
});
const loaded = () => screen.findByRole('heading', { name: 'member@example.com' });

it('keeps a labelled invitation form visible and disabled during initial loading', () => {
  api.getUsers.mockReturnValue(new Promise(() => {}));
  render(<UserManagement />);
  expect(screen.getByText('Loading team members...')).toBeInTheDocument();
  expect(screen.getByRole('form', { name: 'Invite a teammate' })).toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Email address' })).toBeDisabled();
  expect(screen.getByRole('combobox', { name: 'Invite as' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Create invitation link' })).toBeDisabled();
});

it('shows active members and pending invitations with individually labelled actions', async () => {
  render(<UserManagement />);
  await loaded();
  expect(screen.getAllByRole('listitem')).toHaveLength(3);
  expect(screen.getByText('You')).toBeInTheDocument();
  expect(screen.getAllByText('Active')).toHaveLength(2);
  expect(screen.getByText('Pending')).toBeInTheDocument();
  const self = screen.getByRole('combobox', { name: 'Role for admin@example.com' });
  expect(self).toBeDisabled();
  expect(self).toHaveAccessibleDescription('You cannot change your own role or remove yourself.');
  expect(screen.getByRole('button', { name: 'Remove admin@example.com' })).toBeDisabled();
  expect(screen.getByRole('combobox', { name: 'Role for member@example.com' })).toBeEnabled();
  expect(screen.getByRole('button', { name: 'Cancel invitation for pending@example.com' })).toBeEnabled();
  expect(screen.getByRole('textbox', { name: 'Email address' })).toHaveAccessibleDescription(/private link/);
});

it('explains why another last administrator cannot be edited', async () => {
  identity(teamAdministrator(1, 9));
  render(<UserManagement />);
  await loaded();
  const role = screen.getByRole('combobox', { name: 'Role for admin@example.com' });
  expect(role).toBeDisabled();
  expect(role).toHaveAccessibleDescription(/Promote another member/);
  expect(screen.getByRole('button', { name: 'Remove admin@example.com' })).toBeDisabled();
});

it('shows a retryable initial error and supports an empty team', async () => {
  api.getUsers.mockRejectedValueOnce(new Error('Server unavailable')).mockResolvedValue([]);
  render(<UserManagement />);
  expect(await screen.findByText('Unable to load team members')).toBeInTheDocument();
  expect(screen.getByText('Server unavailable')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Refresh team' }));
  expect(await screen.findByText('No team members found.')).toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Email address' })).toBeEnabled();
});

it.each([null, { ...teamAdministrator(), isWorkspaceAdmin: false }])('requires administrator access before reading data: %s', user => {
  identity(user);
  render(<UserManagement />);
  expect(screen.getByText('Workspace administrator access is required.')).toBeInTheDocument();
  expect(api.getUsers).not.toHaveBeenCalled();
});

it('reports role-only drafts and clears navigation constraints on unmount', async () => {
  const status = vi.fn();
  const { unmount } = render(<UserManagement onStatusChange={status} />);
  await loaded();
  await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Invite as' }), WorkspaceRole.WorkspaceAdmin);
  expect(status).toHaveBeenLastCalledWith({ dirty: true, pending: false });
  unmount();
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: false });
});

it('preserves failed invitation drafts and clears them only after a successful retry', async () => {
  api.inviteUser.mockRejectedValueOnce(new Error('Invitation failed'));
  const status = vi.fn();
  render(<UserManagement onStatusChange={status} />);
  await loaded();
  const email = screen.getByRole('textbox', { name: 'Email address' });
  await userEvent.type(email, 'new@example.com');
  await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Invite as' }), WorkspaceRole.WorkspaceAdmin);
  await userEvent.click(screen.getByRole('button', { name: 'Create invitation link' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Invitation failed');
  expect(email).toHaveValue('new@example.com');
  expect(screen.getByRole('combobox', { name: 'Invite as' })).toHaveValue(WorkspaceRole.WorkspaceAdmin);
  await userEvent.click(screen.getByRole('button', { name: 'Create invitation link' }));
  await waitFor(() => expect(email).toHaveValue(''));
  expect(api.inviteUser).toHaveBeenLastCalledWith({ email: 'new@example.com', role: WorkspaceRole.WorkspaceAdmin });
  expect(screen.getByText('Invitation link created. Share it privately with the intended person.')).toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: false });
});

it('creates a link for an email label without treating it as membership identity', async () => {
  render(<UserManagement />);
  await loaded();
  await userEvent.type(screen.getByRole('textbox', { name: 'Email address' }), 'MEMBER@example.com');
  fireEvent.submit(screen.getByRole('form', { name: 'Invite a teammate' }));
  expect(await screen.findByRole('textbox', { name: 'Invitation link' })).toBeInTheDocument();
  expect(api.inviteUser).toHaveBeenCalledWith({ email: 'MEMBER@example.com', role: WorkspaceRole.Normal });
});

it('keeps controls locked and confirmed roles visible until the refresh settles', async () => {
  const write = deferred<void>();
  const read = deferred<ReturnType<typeof team>>();
  api.updateUserRole.mockReturnValue(write.promise);
  api.getUsers.mockResolvedValueOnce(team()).mockReturnValueOnce(read.promise).mockResolvedValue(team());
  const status = vi.fn();
  render(<UserManagement onStatusChange={status} />);
  await loaded();
  const role = screen.getByRole('combobox', { name: 'Role for member@example.com' });
  await userEvent.selectOptions(role, WorkspaceRole.WorkspaceAdmin);
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: true });
  expect(role).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Cancel invitation for pending@example.com' })).toBeDisabled();
  await act(async () => write.resolve());
  expect(role).toHaveValue(WorkspaceRole.WorkspaceAdmin);
  expect(role).toBeDisabled();
  expect(screen.getByText('Refreshing team members…')).toBeInTheDocument();
  await act(async () => read.reject(new Error('Read unavailable')));
  expect(screen.getByText('Unable to refresh team members')).toBeInTheDocument();
  expect(role).toHaveValue(WorkspaceRole.WorkspaceAdmin);
  expect(role).toBeEnabled();
  await userEvent.click(screen.getByRole('button', { name: 'Refresh team' }));
  await waitFor(() => expect(screen.queryByText('Unable to refresh team members')).not.toBeInTheDocument());
  expect(api.updateUserRole).toHaveBeenCalledExactlyOnceWith(2, WorkspaceRole.WorkspaceAdmin);
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: false });
});

it.each([['Remove member@example.com', 2, 'lose access'], ['Cancel invitation for pending@example.com', 3, 'Cancel the invitation']])('confirms %s and retains the confirmed removal if refresh fails', async (label, id, confirmation) => {
  api.getUsers.mockResolvedValueOnce(team()).mockRejectedValue(new Error('Read unavailable'));
  render(<UserManagement />);
  await loaded();
  await userEvent.click(screen.getByRole('button', { name: String(label) }));
  expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining(String(confirmation)));
  await waitFor(() => expect(api.removeUser).toHaveBeenCalledWith(id));
  expect(await screen.findByText('Unable to refresh team members')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: String(label) })).not.toBeInTheDocument();
});

it('does not remove a person when confirmation is cancelled', async () => {
  vi.mocked(window.confirm).mockReturnValue(false);
  render(<UserManagement />);
  await loaded();
  await userEvent.click(screen.getByRole('button', { name: 'Remove member@example.com' }));
  expect(api.removeUser).not.toHaveBeenCalled();
  expect(screen.getAllByRole('listitem')).toHaveLength(3);
});

it.each(['workspace', 'identity'] as const)('resets drafts and cancels obsolete reads on %s change', async change => {
  const oldRead = deferred<ReturnType<typeof team>>();
  api.getUsers.mockReturnValueOnce(oldRead.promise).mockResolvedValue([]);
  const { rerender } = render(<UserManagement />);
  const signal = api.getUsers.mock.calls[0][0]?.signal;
  identity(change === 'workspace' ? { ...teamAdministrator(2), activeWorkspace: null } as unknown as CurrentUser : teamAdministrator(1, 9));
  rerender(<UserManagement />);
  expect(signal?.aborted).toBe(true);
  expect(await screen.findByText('No team members found.')).toBeInTheDocument();
  await act(async () => oldRead.resolve(team()));
  expect(screen.queryByText('member@example.com')).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Email address' })).toHaveValue('');
});

it('discards an old workspace draft and ignores its late write result', async () => {
  const write = deferred<ReturnType<typeof createdInvitation>>();
  api.inviteUser.mockReturnValue(write.promise);
  const { rerender } = render(<UserManagement />);
  await loaded();
  await userEvent.type(screen.getByRole('textbox', { name: 'Email address' }), 'new@example.com');
  await userEvent.click(screen.getByRole('button', { name: 'Create invitation link' }));
  identity(teamAdministrator(2));
  api.getUsers.mockResolvedValue([]);
  rerender(<UserManagement />);
  expect(await screen.findByText('No team members found.')).toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Email address' })).toHaveValue('');
  await act(async () => write.resolve(createdInvitation()));
  expect(api.getUsers).toHaveBeenCalledTimes(2);
  expect(screen.queryByText('Invitation link created. Share it privately with the intended person.')).not.toBeInTheDocument();
});

it('gives separate mounted forms unique labels and hints', async () => {
  render(<><UserManagement /><UserManagement /></>);
  await waitFor(() => expect(screen.getAllByRole('listitem')).toHaveLength(6));
  const forms = screen.getAllByRole('form', { name: 'Invite a teammate' });
  const emails = forms.map(form => within(form).getByRole('textbox', { name: 'Email address' }));
  expect(emails[0].id).not.toBe(emails[1].id);
  for (const email of emails) expect(email).toHaveAccessibleDescription(/private link/);
});

it('recovers an invitation-list failure without disabling member management', async () => {
  api.getInvitations.mockRejectedValueOnce(new Error('Invitations offline')).mockResolvedValue([]);
  render(<UserManagement />);
  await loaded();
  expect(await screen.findByText('Unable to load invitations')).toBeInTheDocument();
  expect(screen.getByRole('combobox', { name: 'Role for member@example.com' })).toBeEnabled();
  await userEvent.click(screen.getByRole('button', { name: 'Refresh invitations' }));
  expect(await screen.findByText('No pending invitations.')).toBeInTheDocument();
});

it('confirms replacement and cancellation of pending links and retains confirmed data if refresh fails', async () => {
  const pending = createdInvitation().invitation;
  api.getInvitations.mockResolvedValueOnce([pending, { ...pending, invitationId: 'other', email: 'other@example.com', role: WorkspaceRole.WorkspaceAdmin }]).mockRejectedValue(new Error('Offline'));
  render(<UserManagement />);
  await loaded();
  const renew = await screen.findByRole('button', { name: 'Create new link for new@example.com' });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await userEvent.click(renew);
  expect(api.inviteUser).not.toHaveBeenCalled();
  await userEvent.click(renew);
  expect(await screen.findByRole('textbox', { name: 'Invitation link' })).toBeInTheDocument();
  expect(screen.getByText('Unable to refresh invitations')).toBeInTheDocument();
  const cancel = screen.getByRole('button', { name: 'Cancel invitation for new@example.com' });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await userEvent.click(cancel);
  expect(api.cancelInvitation).not.toHaveBeenCalled();
  await userEvent.click(cancel);
  await waitFor(() => expect(screen.queryByRole('textbox', { name: 'Invitation link' })).not.toBeInTheDocument());
  expect(api.cancelInvitation).toHaveBeenCalledWith(pending.invitationId);
  await userEvent.click(screen.getByRole('button', { name: 'Refresh invitations' }));
  expect(api.inviteUser).toHaveBeenCalledOnce();
});

it('copies a private link and offers manual copying when clipboard access fails', async () => {
  const writeText = vi.fn().mockRejectedValueOnce(new Error('Clipboard blocked')).mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
  render(<UserManagement />);
  await loaded();
  await userEvent.type(screen.getByRole('textbox', { name: 'Email address' }), 'new@example.com');
  await userEvent.click(screen.getByRole('button', { name: 'Create invitation link' }));
  const link = await screen.findByRole('textbox', { name: 'Invitation link' }) as HTMLInputElement;
  fireEvent.focus(link);
  expect(link.selectionEnd).toBe(link.value.length);
  await userEvent.click(screen.getByRole('button', { name: 'Copy link' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Clipboard blocked');
  await userEvent.click(screen.getByRole('button', { name: 'Copy link' }));
  expect(await screen.findByText('Link copied.')).toBeInTheDocument();
  expect(writeText).toHaveBeenLastCalledWith(expect.stringContaining('#' + createdInvitation().token));
});

it('shows member-action errors without affecting the invitation draft', async () => {
  api.updateUserRole.mockRejectedValueOnce(new Error('Role change failed'));
  api.getInvitations.mockResolvedValue([{ ...createdInvitation().invitation, expiresAt: '2000-01-01T00:00:00Z' }]);
  render(<UserManagement />);
  await loaded();
  expect(await screen.findByText('Member · Expired — create a new link')).toBeInTheDocument();
  await userEvent.type(screen.getByRole('textbox', { name: 'Email address' }), 'draft@example.com');
  await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Role for member@example.com' }), WorkspaceRole.WorkspaceAdmin);
  expect(await screen.findByRole('alert')).toHaveTextContent('Role change failed');
  expect(screen.getByRole('textbox', { name: 'Email address' })).toHaveValue('draft@example.com');
});
