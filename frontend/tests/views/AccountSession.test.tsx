import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import SettingsView from '../../src/views/SettingsView';
import RequireAuth from '../../src/components/common/RequireAuth';
import { UserProvider } from '../../src/contexts/UserContext';
import { WorkspaceSession } from '../../src/contexts/WorkspaceSession';
import { useUser } from '../../src/contexts/useUser';
import { useEditorStatus } from '../../src/data/shared/useEditorStatus';
import { authApi } from '../../src/api/auth';
import { accountApi, type DeleteAccountResponse } from '../../src/api/account';
import { createMockCurrentUser } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';
import type { CurrentUser } from '../../src/utils/types';

const owner = createMockCurrentUser({ email: 'owner@example.test' });
beforeEach(() => {
  vi.stubGlobal('location', { href: '' });
  vi.spyOn(window, 'confirm').mockReturnValue(false);
  vi.spyOn(authApi, 'getCurrentUser').mockResolvedValue(owner);
  vi.spyOn(authApi, 'logout').mockResolvedValue(undefined);
  vi.spyOn(accountApi, 'getDeletionInfo').mockResolvedValue({ userId: owner.userId, email: owner.email,
    workspaceMemberships: [], workspacesRequiringAction: 0, canDeleteImmediately: true });
  vi.spyOn(accountApi, 'deleteAccount').mockResolvedValue({ success: true });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function Identity() { const { user } = useUser(); return <output aria-label="Current account">{user?.email ?? 'Signed out'}</output>; }
function Draft() { useEditorStatus(true, false); return <p>Another editor has a draft</p>; }
function show(draft = false) {
  const router = createMemoryRouter([
    { path: '/settings', element: <RequireAuth><SettingsView /></RequireAuth> },
    { path: '/collections', element: <h1>Collections</h1> },
  ], { initialEntries: ['/collections', '/settings?section=account'], initialIndex: 1 });
  render(<UserProvider><Identity />{draft && <Draft />}<WorkspaceSession navigate={router.navigate}>
    <RouterProvider router={router} />
  </WorkspaceSession></UserProvider>);
  return router;
}
async function confirm() {
  await userEvent.click(await screen.findByRole('button', { name: 'Delete My Account' }));
  fireEvent.change(await screen.findByPlaceholderText(owner.email), { target: { value: owner.email } });
  await userEvent.click(screen.getByRole('button', { name: 'Delete Account' }));
}
function closing() {
  const event = new Event('beforeunload', { cancelable: true });
  window.dispatchEvent(event);
  return event.defaultPrevented;
}

it('protects navigation through deletion, then permits the confirmed exit without redundant network requests', async () => {
  const write = deferred<DeleteAccountResponse>();
  vi.mocked(accountApi.deleteAccount).mockReturnValue(write.promise);
  const router = show();
  await confirm();
  expect(document.querySelector('.session-change__content')).toHaveAttribute('inert');
  expect(screen.getByRole('button', { name: 'Sign Out' })).toBeDisabled();
  expect(within(screen.getByRole('navigation', { name: 'Settings navigation' })).getByRole('button', { name: /Dashboard/ })).toBeDisabled();
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/settings');
  expect(closing()).toBe(true);
  expect(window.confirm).not.toHaveBeenCalled();
  await act(async () => write.resolve({ success: true }));
  expect(window.location.href).toBe('/');
  expect(closing()).toBe(false);
  expect(document.querySelector('.session-change__content')).toHaveAttribute('inert');
  expect(authApi.logout).not.toHaveBeenCalled();
  expect(authApi.getCurrentUser).toHaveBeenCalledOnce();
  expect(accountApi.deleteAccount).toHaveBeenCalledExactlyOnceWith({ confirmEmail: owner.email, workspaceActions: [] });
});

it('honors unrelated unsaved drafts before attempting account deletion', async () => {
  show(true);
  await confirm();
  expect(await screen.findByRole('alert')).toHaveTextContent('Account deletion cancelled');
  expect(window.confirm).toHaveBeenCalledExactlyOnceWith('You have unsaved changes. Discard them?');
  expect(accountApi.deleteAccount).not.toHaveBeenCalled();
  expect(authApi.getCurrentUser).toHaveBeenCalledOnce();
  expect(screen.getByText('Another editor has a draft')).toBeInTheDocument();
});

it.each([false, true])('reconciles a lost deletion response with an anonymous session, recovery required: %s', async recovery => {
  vi.mocked(accountApi.deleteAccount).mockRejectedValue(new Error('Response lost'));
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(owner);
  if (recovery) vi.mocked(authApi.getCurrentUser).mockRejectedValueOnce(new Error('Session unavailable'));
  vi.mocked(authApi.getCurrentUser).mockResolvedValue(null);
  const router = show();
  await confirm();
  if (recovery) {
    const dialog = await screen.findByRole('dialog', { name: 'Updating your session' });
    expect(within(dialog).getByRole('alert')).toHaveTextContent('Session unavailable');
    expect(document.querySelector('.session-change__content')).toHaveAttribute('inert');
    fireEvent(dialog, new Event('cancel', { bubbles: true, cancelable: true }));
    expect(dialog).toHaveAttribute('open');
    await act(async () => { await router.navigate('/collections'); });
    expect(router.state.location.pathname).toBe('/settings');
    expect(closing()).toBe(true);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Retry session refresh' }));
  }
  await waitFor(() => expect(window.location.href).toBe('/'));
  expect(screen.getByLabelText('Current account')).toHaveTextContent('Signed out');
  expect(screen.queryByRole('heading', { name: 'Settings' })).not.toBeInTheDocument();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(closing()).toBe(false);
  expect(authApi.getCurrentUser).toHaveBeenCalledTimes(recovery ? 3 : 2);
  expect(accountApi.deleteAccount).toHaveBeenCalledOnce();
  expect(authApi.logout).not.toHaveBeenCalled();
});

it('restores navigation only after a failed write is reconciled to the unchanged account', async () => {
  const read = deferred<CurrentUser | null>();
  vi.mocked(accountApi.deleteAccount).mockRejectedValue(new Error('Workspace changed'));
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(owner).mockReturnValueOnce(read.promise);
  const router = show();
  await confirm();
  expect(document.querySelector('.session-change__content')).toHaveAttribute('inert');
  await act(async () => read.resolve(owner));
  expect(await screen.findByRole('alert')).toHaveTextContent('Workspace changed');
  expect(document.querySelector('.session-change__content')).not.toHaveAttribute('inert');
  expect(screen.getByLabelText('Current account')).toHaveTextContent(owner.email);
  expect(window.location.href).toBe('');
  await userEvent.click(screen.getByRole('button', { name: 'Review workspace choices' }));
  expect(await screen.findByPlaceholderText(owner.email)).toHaveValue('');
  expect(accountApi.deleteAccount).toHaveBeenCalledOnce();
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/collections');
});

it('keeps useful review guidance after a failed session read recovers to the existing account', async () => {
  vi.mocked(accountApi.deleteAccount).mockRejectedValue(new Error('Response lost'));
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(owner).mockRejectedValueOnce(new Error('Session unavailable')).mockResolvedValue(owner);
  show();
  await confirm();
  await userEvent.click(await screen.findByRole('button', { name: 'Retry session refresh' }));
  await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Updating your session' })).not.toBeInTheDocument());
  expect(screen.getByRole('alert')).toHaveTextContent('Review workspace choices before trying account deletion again.');
  expect(screen.getByRole('alert')).not.toHaveTextContent('Session unavailable');
  expect(document.querySelector('.session-change__content')).not.toHaveAttribute('inert');
  expect(window.location.href).toBe('');
  expect(accountApi.deleteAccount).toHaveBeenCalledOnce();
});

it('keeps account deletion available when no active workspace remains', async () => {
  vi.mocked(authApi.getCurrentUser).mockResolvedValue({ ...owner, activeWorkspace: null, workspaceId: null, workspaces: [], hasCompletedWelcome: false });
  show();
  await confirm();
  await waitFor(() => expect(window.location.href).toBe('/'));
  expect(accountApi.deleteAccount).toHaveBeenCalledOnce();
  expect(authApi.logout).not.toHaveBeenCalled();
});
