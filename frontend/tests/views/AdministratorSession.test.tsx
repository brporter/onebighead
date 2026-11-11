import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import SystemAdmin from '../../src/views/SystemAdmin';
import { UserProvider } from '../../src/contexts/UserContext';
import { useUser } from '../../src/contexts/useUser';
import { authApi } from '../../src/api/auth';
import { adminApi } from '../../src/api/admin';
import { createMockCurrentUser } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';
import type { CurrentUser, UserSummary } from '../../src/utils/types';

const administrator = createMockCurrentUser({ userId: 7, email: 'admin@example.test', isSystemAdministrator: true });
const self: UserSummary = { userId: 7, email: administrator.email, workspaceId: 1, workspaceName: 'Library',
  identityProvider: 'Google', isSystemAdministrator: true, createdAt: '2026-01-01' };
const ordinary = { ...administrator, isSystemAdministrator: false };
beforeEach(() => {
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  vi.spyOn(authApi, 'getCurrentUser').mockResolvedValue(administrator);
  vi.spyOn(authApi, 'logout').mockResolvedValue(undefined);
  vi.spyOn(adminApi, 'getWorkspaces').mockResolvedValue([]);
  vi.spyOn(adminApi, 'getUsers').mockResolvedValue([self]);
  vi.spyOn(adminApi, 'deleteUser').mockResolvedValue(undefined);
  vi.spyOn(adminApi, 'setAdminStatus').mockResolvedValue({ ...self, isSystemAdministrator: false });
});
afterEach(() => vi.restoreAllMocks());

function Home() {
  const { user } = useUser();
  return <h1>{user ? 'Account home' : 'Signed out'}</h1>;
}
function show() {
  const router = createMemoryRouter([{ path: '/admin', element: <SystemAdmin /> }, { path: '/', element: <Home /> }],
    { initialEntries: ['/', '/admin'], initialIndex: 1 });
  render(<UserProvider><RouterProvider router={router} /></UserProvider>);
  return router;
}
async function openUsers() {
  await userEvent.click(await screen.findByRole('button', { name: 'Users' }));
  return screen.findByRole('checkbox', { name: 'System administrator for admin@example.test' });
}

it('identifies the acting account and can cancel removal of its administrator permission', async () => {
  show();
  const toggle = await openUsers();
  expect(screen.getByRole('rowheader')).toHaveTextContent('admin@example.test (you)');
  vi.mocked(window.confirm).mockReturnValue(false);
  await userEvent.click(toggle);
  expect(toggle).toBeChecked();
  expect(window.confirm).toHaveBeenCalledExactlyOnceWith('Remove your system administrator access? You will leave administration after this change.');
  expect(adminApi.setAdminStatus).not.toHaveBeenCalled();
  expect(authApi.getCurrentUser).toHaveBeenCalledOnce();
});

it('retires administrator controls only after confirming a successful self-demotion', async () => {
  const write = deferred<UserSummary>();
  const read = deferred<CurrentUser | null>();
  vi.mocked(adminApi.setAdminStatus).mockReturnValue(write.promise);
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(administrator).mockReturnValueOnce(read.promise);
  const router = show();
  await userEvent.click(await openUsers());
  expect(document.querySelector('.session-change__content')).toHaveAttribute('inert');
  expect(screen.getByRole('button', { name: 'Sign Out' })).toBeDisabled();
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/admin');
  await act(async () => write.resolve({ ...self, isSystemAdministrator: false }));
  expect(await screen.findByRole('dialog')).toHaveTextContent('confirm your session');
  expect(screen.getByRole('heading', { name: 'System Administration' })).toBeInTheDocument();
  await act(async () => read.resolve(ordinary));
  expect(await screen.findByRole('heading', { name: 'Account home' })).toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'System Administration' })).not.toBeInTheDocument();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(adminApi.setAdminStatus).toHaveBeenCalledExactlyOnceWith(7, false);
  expect(adminApi.getUsers).toHaveBeenCalledOnce();
  const unload = new Event('beforeunload', { cancelable: true });
  window.dispatchEvent(unload);
  expect(unload.defaultPrevented).toBe(false);
});

it.each(['demotion', 'deletion'] as const)('recovers a lost self-%s response using reads without repeating the command', async action => {
  const command = action === 'demotion' ? vi.mocked(adminApi.setAdminStatus) : vi.mocked(adminApi.deleteUser);
  command.mockRejectedValue(new Error('Response lost'));
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(administrator).mockRejectedValueOnce(new Error('Session unavailable'))
    .mockResolvedValue(action === 'demotion' ? ordinary : null);
  show();
  const toggle = await openUsers();
  await userEvent.click(action === 'demotion' ? toggle : screen.getByRole('button', { name: 'Delete user admin@example.test' }));
  expect(await screen.findByRole('dialog')).toHaveTextContent('Session unavailable');
  expect(document.querySelector('.session-change__content')).toHaveAttribute('inert');
  expect(screen.getByRole('button', { name: 'Workspaces' })).toBeDisabled();
  await userEvent.click(screen.getByRole('button', { name: 'Retry session refresh' }));
  expect(await screen.findByRole('heading', { name: action === 'demotion' ? 'Account home' : 'Signed out' })).toBeInTheDocument();
  expect(command).toHaveBeenCalledOnce();
  expect(authApi.getCurrentUser).toHaveBeenCalledTimes(3);
  expect(adminApi.getUsers).toHaveBeenCalledOnce();
  expect(authApi.logout).not.toHaveBeenCalled();
});

it('confirms self-deletion before writing and clears the account after a successful deletion', async () => {
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(administrator).mockResolvedValue(null);
  show();
  await openUsers();
  const remove = screen.getByRole('button', { name: 'Delete user admin@example.test' });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await userEvent.click(remove);
  expect(window.confirm).toHaveBeenLastCalledWith('Permanently delete your account and memberships? You will be signed out.');
  expect(adminApi.deleteUser).not.toHaveBeenCalled();
  await userEvent.click(remove);
  expect(await screen.findByRole('heading', { name: 'Signed out' })).toBeInTheDocument();
  expect(adminApi.deleteUser).toHaveBeenCalledExactlyOnceWith(7);
});

it('keeps the confirmed administrator identity after a denied change and permits a later retry', async () => {
  vi.mocked(adminApi.setAdminStatus).mockRejectedValueOnce(new Error('Denied')).mockResolvedValue({ ...self, isSystemAdministrator: false });
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(administrator).mockResolvedValueOnce(administrator).mockResolvedValue(ordinary);
  show();
  const toggle = await openUsers();
  await userEvent.click(toggle);
  expect(await screen.findByRole('alert')).toHaveTextContent('Denied');
  expect(toggle).toBeChecked();
  expect(toggle).toBeEnabled();
  fireEvent.click(toggle);
  await waitFor(() => expect(screen.getByRole('heading', { name: 'Account home' })).toBeInTheDocument());
  expect(adminApi.setAdminStatus).toHaveBeenCalledTimes(2);
});
