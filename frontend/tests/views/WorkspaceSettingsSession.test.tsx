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
import { workspacesApi } from '../../src/api/workspaces';
import { exportApi } from '../../src/api/export';
import { themesApi } from '../../src/api/themes';
import { saveDownload } from '../../src/utils/saveDownload';
import type { WorkspaceStats } from '../../src/api/workspaces';
import { createMockCollectionTheme, createMockCurrentUser, createMockWorkspaceMembership } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';
import { WorkspaceRole } from '../../src/utils/types';

vi.mock('../../src/utils/saveDownload', () => ({ saveDownload: vi.fn() }));

const home = createMockWorkspaceMembership({ workspaceId: 1, workspaceName: 'Home', workspaceRole: WorkspaceRole.WorkspaceAdmin });
const other = createMockWorkspaceMembership({ workspaceId: 2, workspaceName: 'Shared', workspaceRole: WorkspaceRole.Normal });
const archived = createMockWorkspaceMembership({ workspaceId: 3, workspaceName: 'Archive', workspaceRole: WorkspaceRole.WorkspaceAdmin });
const owner = createMockCurrentUser({ activeWorkspace: home, workspaces: [home, other] });
const reload = vi.fn();
beforeEach(() => {
  sessionStorage.clear();
  reload.mockReset();
  vi.stubGlobal('location', { href: '', reload });
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  vi.spyOn(authApi, 'getCurrentUser').mockResolvedValue(owner);
  vi.spyOn(authApi, 'logout').mockResolvedValue(undefined);
  vi.spyOn(workspacesApi, 'getRestorableWorkspaces').mockResolvedValue([{ workspaceId: 3, name: 'Archive', deletedAt: '2026-11-01', daysRemaining: 21,
    stats: { collectionCount: 1, itemCount: 2, categoryCount: 3, imageCount: 4 } }]);
  vi.spyOn(workspacesApi, 'switch').mockResolvedValue({ success: true, workspaceId: 2, workspaceName: 'Shared' });
  vi.spyOn(workspacesApi, 'leave').mockResolvedValue({ success: true });
  vi.spyOn(workspacesApi, 'restoreWorkspace').mockResolvedValue({ workspaceId: 3, name: 'Archive' });
  vi.spyOn(workspacesApi, 'getStats').mockResolvedValue({ workspaceId: 1, workspaceName: 'Home', collectionCount: 1, itemCount: 2, categoryCount: 3, imageCount: 4, userCount: 1, adminCount: 1 });
  vi.spyOn(workspacesApi, 'deleteWorkspace').mockResolvedValue({ success: true });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function Identity() { const { user } = useUser(); return <output aria-label="Current workspace">{user?.activeWorkspace?.workspaceName ?? 'None'}</output>; }
function Draft() { useEditorStatus(true, false); return <p>Another editor has a draft</p>; }
function show(draft = false) {
  const router = createMemoryRouter([
    { path: '/settings', element: <RequireAuth><SettingsView /></RequireAuth> },
    { path: '/collections', element: <h1>Collections</h1> },
  ], { initialEntries: ['/collections', '/settings?section=workspaces'], initialIndex: 1 });
  render(<UserProvider><Identity />{draft && <Draft />}<WorkspaceSession navigate={router.navigate}>
    <RouterProvider router={router} />
  </WorkspaceSession></UserProvider>);
  return router;
}
function closing() {
  const event = new Event('beforeunload', { cancelable: true });
  window.dispatchEvent(event);
  return event.defaultPrevented;
}

it('protects workspace creation drafts, saving and refresh recovery, then enters the new session without reloading or creating twice', async () => {
  const created = createMockWorkspaceMembership({ workspaceId: 5, workspaceName: 'Study', workspaceRole: WorkspaceRole.WorkspaceAdmin });
  const response = { workspaceId: 5, workspaceName: 'Study', workspaceRole: WorkspaceRole.WorkspaceAdmin, collectionId: 12, collectionName: 'My Collection' };
  const write = deferred<typeof response>();
  vi.spyOn(themesApi, 'getAll').mockResolvedValue([createMockCollectionTheme({ themeId: 1, name: 'General' })]);
  vi.spyOn(workspacesApi, 'setup').mockReturnValue(write.promise);
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(owner).mockRejectedValueOnce(new Error('Setup session offline')).mockResolvedValue(
    { ...owner, workspaceId: 5, workspaceName: 'Study', isWorkspaceAdmin: true, activeWorkspace: created, workspaces: [home, other, created] });
  const router = show();
  await userEvent.click(await screen.findByRole('button', { name: '+ Create New Workspace' }));
  await userEvent.type(screen.getByRole('textbox', { name: /New Workspace Name/ }), 'Study');
  vi.mocked(window.confirm).mockReturnValue(false);
  await userEvent.click(screen.getByRole('button', { name: /Dashboard/ }));
  expect(router.state.location.search).toBe('?section=workspaces');
  expect(screen.getByRole('textbox', { name: /New Workspace Name/ })).toHaveValue('Study');
  expect(closing()).toBe(true);
  await userEvent.click(screen.getByRole('button', { name: 'Next' }));
  await userEvent.click(screen.getByRole('button', { name: 'Next' }));
  await userEvent.click(screen.getByRole('button', { name: 'Create Workspace' }));
  vi.mocked(window.confirm).mockClear();
  expect(screen.getByRole('button', { name: /Dashboard/ })).toBeDisabled();
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/settings');
  expect(window.confirm).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
  expect(authApi.logout).not.toHaveBeenCalled();
  await act(async () => write.resolve(response));
  expect(await screen.findByText('Setup session offline')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /Dashboard/ })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Close setup' })).toBeEnabled();
  expect(closing()).toBe(true);
  await userEvent.click(screen.getByRole('button', { name: 'Continue setup' }));
  await screen.findByRole('heading', { name: 'Collections' });
  expect(screen.getByLabelText('Current workspace')).toHaveTextContent('Study');
  expect(workspacesApi.setup).toHaveBeenCalledExactlyOnceWith({ requestId: expect.any(String), workspaceName: 'Study', collectionName: undefined, collectionDescription: undefined, themeId: 1 });
  expect(authApi.getCurrentUser).toHaveBeenCalledTimes(3);
  expect(closing()).toBe(false);
  expect(reload).not.toHaveBeenCalled();
  expect(window.location.href).toBe('');
});

it.each([
  ['switch', 'Switch to Shared'], ['leave', 'Leave Shared'], ['restoreWorkspace', 'Restore Archive'],
] as const)('protects navigation through %s and retries only the failed session read', async (method, label) => {
  const write = deferred<{ success: boolean; workspaceId: number; workspaceName: string; name: string }>();
  vi.mocked(workspacesApi[method]).mockReturnValue(write.promise);
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(owner).mockRejectedValueOnce(new Error('Session offline')).mockResolvedValue(owner);
  const router = show();
  await userEvent.click(await screen.findByRole('button', { name: label }));
  vi.mocked(window.confirm).mockClear();
  expect(document.querySelector('.session-change__content')).toHaveAttribute('inert');
  expect(screen.getByRole('button', { name: 'Sign Out' })).toBeDisabled();
  expect(within(screen.getByRole('navigation', { name: 'Settings navigation' })).getByRole('button', { name: /Dashboard/ })).toBeDisabled();
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/settings');
  expect(closing()).toBe(true);
  expect(window.confirm).not.toHaveBeenCalled();
  await act(async () => write.reject(new Error('Response lost')));
  const dialog = await screen.findByRole('dialog', { name: 'Updating your session' });
  expect(within(dialog).getByRole('alert')).toHaveTextContent('Session offline');
  fireEvent(dialog, new Event('cancel', { bubbles: true, cancelable: true }));
  expect(dialog).toHaveAttribute('open');
  await act(async () => { await router.navigate('/collections'); });
  expect(router.state.location.pathname).toBe('/settings');
  expect(closing()).toBe(true);
  await userEvent.click(within(dialog).getByRole('button', { name: 'Retry session refresh' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(document.querySelector('.session-change__content')).not.toHaveAttribute('inert');
  expect(screen.getByRole('alert')).toHaveTextContent('Review your workspaces before trying again.');
  expect(closing()).toBe(false);
  expect(workspacesApi[method]).toHaveBeenCalledOnce();
  expect(authApi.getCurrentUser).toHaveBeenCalledTimes(3);
  expect(workspacesApi.getRestorableWorkspaces).toHaveBeenCalledTimes(2);
  expect(reload).not.toHaveBeenCalled();
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/collections');
});

it('uses a confirmed different workspace after a lost switch response without replaying the switch', async () => {
  vi.mocked(workspacesApi.switch).mockRejectedValue(new Error('Response lost'));
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(owner).mockResolvedValue({ ...owner, activeWorkspace: other, workspaceId: 2 });
  const router = show();
  await userEvent.click(await screen.findByRole('button', { name: 'Switch to Shared' }));
  await screen.findByRole('heading', { name: 'Collections' });
  expect(router.state.location.pathname).toBe('/collections');
  expect(screen.getByLabelText('Current workspace')).toHaveTextContent('Shared');
  expect(workspacesApi.switch).toHaveBeenCalledExactlyOnceWith(2);
  expect(authApi.getCurrentUser).toHaveBeenCalledTimes(2);
  expect(closing()).toBe(false);
  expect(reload).not.toHaveBeenCalled();
});

it('reconciles a committed restoration after a lost response and removes the stale restore action', async () => {
  vi.mocked(workspacesApi.restoreWorkspace).mockRejectedValue(new Error('Response lost'));
  vi.mocked(workspacesApi.getRestorableWorkspaces).mockResolvedValueOnce([{ workspaceId: 3, name: 'Archive', deletedAt: '2026-11-01', daysRemaining: 21,
    stats: { collectionCount: 1, itemCount: 2, categoryCount: 3, imageCount: 4 } }]).mockResolvedValue([]);
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(owner).mockResolvedValue({ ...owner, workspaces: [home, other, archived] });
  show();
  await userEvent.click(await screen.findByRole('button', { name: 'Restore Archive' }));
  await screen.findByText('No workspaces to restore');
  expect(screen.queryByRole('button', { name: 'Restore Archive' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Switch to Archive' })).toBeEnabled();
  expect(screen.getAllByRole('article', { name: 'Archive' })).toHaveLength(1);
  expect(workspacesApi.restoreWorkspace).toHaveBeenCalledExactlyOnceWith(3);
  expect(reload).not.toHaveBeenCalled();
});

it('honors other unsaved editors before performing a workspace change', async () => {
  vi.mocked(window.confirm).mockReturnValue(false);
  show(true);
  await userEvent.click(await screen.findByRole('button', { name: 'Switch to Shared' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Workspace change cancelled');
  expect(window.confirm).toHaveBeenCalledExactlyOnceWith('You have unsaved changes. Discard them?');
  expect(workspacesApi.switch).not.toHaveBeenCalled();
  expect(authApi.getCurrentUser).toHaveBeenCalledOnce();
});

it('ends the old UI when recovery confirms an anonymous session', async () => {
  vi.mocked(workspacesApi.leave).mockRejectedValue(new Error('Response lost'));
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(owner).mockResolvedValue(null);
  show();
  await userEvent.click(await screen.findByRole('button', { name: 'Leave Shared' }));
  await waitFor(() => expect(window.location.href).toBe('/'));
  expect(screen.queryByRole('heading', { name: 'Settings' })).not.toBeInTheDocument();
  expect(workspacesApi.leave).toHaveBeenCalledExactlyOnceWith(2);
  expect(authApi.logout).not.toHaveBeenCalled();
  expect(closing()).toBe(false);
});

it('protects workspace drafts across Settings, history, sign-out and closing the page', async () => {
  const router = show();
  await userEvent.click(await screen.findByRole('button', { name: 'Edit Home' }));
  const dialog = await screen.findByRole('dialog', { name: 'Edit Workspace' });
  fireEvent.change(within(dialog).getByRole('textbox', { name: 'Workspace Name' }), { target: { value: 'Unsaved name' } });
  vi.mocked(window.confirm).mockReturnValue(false);
  await userEvent.click(within(screen.getByRole('navigation', { name: 'Settings navigation' })).getByRole('button', { name: /Dashboard/ }));
  expect(router.state.location.search).toBe('?section=workspaces');
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/settings');
  await userEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
  expect(authApi.logout).not.toHaveBeenCalled();
  expect(closing()).toBe(true);
  expect(within(dialog).getByRole('textbox', { name: 'Workspace Name' })).toHaveValue('Unsaved name');
  vi.mocked(window.confirm).mockReturnValue(true);
  await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(closing()).toBe(false);
});

it.each([true, false])('keeps workspace edits protected through read-only recovery (confirmed: %s)', async confirmed => {
  const write = deferred<{ workspaceId: number; workspaceName: string }>();
  vi.spyOn(workspacesApi, 'update').mockReturnValue(write.promise);
  const updated = { ...home, workspaceName: 'Renamed', slug: 'home' };
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(owner).mockRejectedValueOnce(new Error('Session offline'))
    .mockResolvedValue({ ...owner, activeWorkspace: updated, workspaces: [updated, other] });
  const router = show();
  await userEvent.click(await screen.findByRole('button', { name: 'Edit Home' }));
  const dialog = await screen.findByRole('dialog', { name: 'Edit Workspace' });
  fireEvent.change(within(dialog).getByRole('textbox', { name: 'Workspace Name' }), { target: { value: 'Renamed' } });
  fireEvent.change(within(dialog).getByRole('textbox', { name: 'Gallery URL Slug' }), { target: { value: 'home' } });
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
  expect(within(dialog).getByRole('textbox', { name: 'Workspace Name' })).toBeDisabled();
  expect(within(screen.getByRole('navigation', { name: 'Settings navigation' })).getByRole('button', { name: /Dashboard/ })).toBeDisabled();
  expect(closing()).toBe(true);
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/settings');
  await act(async () => { if (confirmed) write.resolve({ workspaceId: 1, workspaceName: 'Renamed' }); else write.reject(new Error('Response lost')); });
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('Session offline');
  expect(within(dialog).getByRole('alert')).toHaveFocus();
  expect(within(dialog).getByRole('button', { name: 'Close' })).toBeDisabled();
  fireEvent(dialog, new Event('cancel', { bubbles: true, cancelable: true }));
  expect(dialog).toHaveAttribute('open');
  expect(closing()).toBe(true);
  await userEvent.click(within(dialog).getByRole('button', { name: 'Retry workspace refresh' }));
  await waitFor(() => expect(screen.getByLabelText('Current workspace')).toHaveTextContent('Renamed'));
  expect(workspacesApi.update).toHaveBeenCalledExactlyOnceWith(1, { name: 'Renamed', slug: 'home' });
  expect(authApi.getCurrentUser).toHaveBeenCalledTimes(3);
  expect(reload).not.toHaveBeenCalled();
  expect(router.state.location.pathname).toBe('/settings');
  if (confirmed) {
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(closing()).toBe(false);
  } else {
    expect(within(dialog).getByRole('alert')).toHaveTextContent('Response lost');
    expect(within(dialog).getByRole('alert')).toHaveFocus();
    expect(within(dialog).getByRole('textbox', { name: 'Workspace Name' })).toHaveValue('Renamed');
    expect(within(dialog).getByRole('textbox', { name: 'Workspace Name' })).toBeEnabled();
    expect(closing()).toBe(true);
  }
});

it('protects navigation while preparing deletion and exporting a backup', async () => {
  const stats = deferred<WorkspaceStats>();
  const backup = deferred<{ blob: Blob; filename: string }>();
  vi.mocked(workspacesApi.getStats).mockReturnValueOnce(stats.promise);
  vi.spyOn(exportApi, 'downloadExport').mockReturnValue(backup.promise);
  const router = show();
  await userEvent.click(await screen.findByRole('button', { name: 'Delete Home' }));
  await screen.findByText('Loading deletion information…');
  expect(closing()).toBe(true);
  expect(within(screen.getByRole('navigation', { name: 'Settings navigation' })).getByRole('button', { name: /Dashboard/ })).toBeDisabled();
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/settings');
  await act(async () => stats.resolve({ workspaceId: 1, workspaceName: 'Home', collectionCount: 1, categoryCount: 2, itemCount: 3, imageCount: 0, userCount: 1, adminCount: 1 }));
  const dialog = screen.getByRole('dialog', { name: 'Delete "Home"' });
  await userEvent.click(within(dialog).getByRole('button', { name: 'Download Export' }));
  expect(closing()).toBe(true);
  expect(within(dialog).getByRole('button', { name: 'Cancel' })).toBeDisabled();
  await act(async () => { await router.navigate('/collections'); });
  expect(router.state.location.pathname).toBe('/settings');
  const file = { blob: new Blob(['backup']), filename: 'home.zip' };
  await act(async () => backup.resolve(file));
  expect(saveDownload).toHaveBeenCalledWith(file);
  expect(closing()).toBe(false);
  await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(workspacesApi.deleteWorkspace).not.toHaveBeenCalled();
});

it.each([true, false])('recovers a committed workspace deletion without repeating it (confirmed: %s)', async confirmed => {
  const write = deferred<{ success: boolean }>();
  vi.mocked(workspacesApi.deleteWorkspace).mockReturnValue(write.promise);
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(owner).mockRejectedValueOnce(new Error('Session offline'))
    .mockResolvedValue({ ...owner, activeWorkspace: other, workspaces: [other], workspaceId: 2 });
  const router = show();
  await userEvent.click(await screen.findByRole('button', { name: 'Delete Home' }));
  const confirmation = await screen.findByRole('dialog', { name: 'Delete "Home"' });
  await userEvent.click(await within(confirmation).findByRole('checkbox'));
  await userEvent.click(within(confirmation).getByRole('button', { name: 'Delete Workspace' }));
  expect(document.querySelector('.session-change__content')).toHaveAttribute('inert');
  expect(closing()).toBe(true);
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/settings');
  await act(async () => { if (confirmed) write.resolve({ success: true }); else write.reject(new Error('Response lost')); });
  const recovery = await screen.findByRole('dialog', { name: 'Updating your session' });
  const retry = await within(recovery).findByRole('button', { name: 'Retry session refresh' });
  expect(within(recovery).getByRole('alert')).toHaveTextContent('Session offline');
  expect(closing()).toBe(true);
  await userEvent.click(retry);
  await screen.findByRole('heading', { name: 'Collections' });
  expect(screen.getByLabelText('Current workspace')).toHaveTextContent('Shared');
  expect(workspacesApi.deleteWorkspace).toHaveBeenCalledExactlyOnceWith(1);
  expect(authApi.getCurrentUser).toHaveBeenCalledTimes(3);
  expect(authApi.logout).not.toHaveBeenCalled();
  expect(reload).not.toHaveBeenCalled();
  expect(closing()).toBe(false);
});

it('refreshes the recovery list after deleting a non-active workspace and preserves current scope', async () => {
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce({ ...owner, workspaces: [home, other, archived] }).mockResolvedValue(owner);
  vi.mocked(workspacesApi.getRestorableWorkspaces).mockResolvedValueOnce([]).mockResolvedValue([{ workspaceId: 3, name: 'Archive', deletedAt: '2026-11-01', daysRemaining: 21,
    stats: { collectionCount: 1, itemCount: 2, categoryCount: 3, imageCount: 4 } }]);
  const router = show();
  await userEvent.click(await screen.findByRole('button', { name: 'Delete Archive' }));
  const confirmation = await screen.findByRole('dialog', { name: 'Delete "Archive"' });
  await userEvent.click(await within(confirmation).findByRole('checkbox'));
  expect(within(confirmation).queryByRole('button', { name: 'Download Export' })).not.toBeInTheDocument();
  await userEvent.click(within(confirmation).getByRole('button', { name: 'Delete Workspace' }));
  await screen.findByRole('button', { name: 'Restore Archive' });
  expect(screen.queryByRole('button', { name: 'Delete Archive' })).not.toBeInTheDocument();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(router.state.location.pathname).toBe('/settings');
  expect(screen.getByLabelText('Current workspace')).toHaveTextContent('Home');
  expect(workspacesApi.getRestorableWorkspaces).toHaveBeenCalledTimes(2);
  expect(workspacesApi.deleteWorkspace).toHaveBeenCalledExactlyOnceWith(3);
  expect(reload).not.toHaveBeenCalled();
});

it('ends the session after deleting the last workspace without an extra logout', async () => {
  vi.mocked(workspacesApi.deleteWorkspace).mockResolvedValue({ success: true, userSoftDeleted: true });
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(owner).mockResolvedValue(null);
  show();
  await userEvent.click(await screen.findByRole('button', { name: 'Delete Home' }));
  const confirmation = await screen.findByRole('dialog', { name: 'Delete "Home"' });
  await userEvent.click(await within(confirmation).findByRole('checkbox'));
  await userEvent.click(within(confirmation).getByRole('button', { name: 'Delete Workspace' }));
  await waitFor(() => expect(window.location.href).toBe('/'));
  expect(screen.queryByRole('heading', { name: 'Settings' })).not.toBeInTheDocument();
  expect(authApi.logout).not.toHaveBeenCalled();
  expect(workspacesApi.deleteWorkspace).toHaveBeenCalledExactlyOnceWith(1);
  expect(closing()).toBe(false);
});

it('honors other unsaved drafts before deleting a workspace', async () => {
  vi.mocked(window.confirm).mockReturnValue(false);
  show(true);
  await userEvent.click(await screen.findByRole('button', { name: 'Delete Home' }));
  const confirmation = await screen.findByRole('dialog', { name: 'Delete "Home"' });
  await userEvent.click(await within(confirmation).findByRole('checkbox'));
  await userEvent.click(within(confirmation).getByRole('button', { name: 'Delete Workspace' }));
  expect(await within(confirmation).findByRole('alert')).toHaveTextContent('Workspace deletion cancelled');
  expect(window.confirm).toHaveBeenCalledExactlyOnceWith('You have unsaved changes. Discard them?');
  expect(workspacesApi.deleteWorkspace).not.toHaveBeenCalled();
  expect(authApi.getCurrentUser).toHaveBeenCalledOnce();
});
