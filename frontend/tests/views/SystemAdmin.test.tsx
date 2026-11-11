import type { ReactNode } from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import SystemAdmin from '../../src/views/SystemAdmin';
import { useUser } from '../../src/contexts/useUser';
import { adminApi } from '../../src/api/admin';
import { createMockCurrentUser, createMockItemTemplate } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';
import type { UserSummary, WorkspaceSummary, ItemTemplate } from '../../src/utils/types';
import type { EditorStatusListener } from '../../src/data/shared/useEditorStatus';
import { SessionChangesProvider } from '../../src/contexts/SessionChangesProvider';
import { useEditorStatus } from '../../src/data/shared/useEditorStatus';

vi.mock('../../src/contexts/useUser', () => ({ useUser: vi.fn() }));
vi.mock('../../src/api/admin', () => ({ adminApi: {
  getWorkspaces: vi.fn(), deleteWorkspace: vi.fn(), getUsers: vi.fn(), deleteUser: vi.fn(), setAdminStatus: vi.fn(),
  getSystemTemplates: vi.fn(), createSystemTemplate: vi.fn(), updateSystemTemplate: vi.fn(), deleteSystemTemplate: vi.fn(),
} }));
vi.mock('../../src/components/support/AdminSupportSection', () => ({ AdminSupportSection: ({ onStatusChange }: { onStatusChange: EditorStatusListener }) => <div>
  <p>Support workflow</p>
  <button onClick={() => onStatusChange({ dirty: true, pending: false })}>Draft reply</button>
  <button onClick={() => onStatusChange({ dirty: true, pending: true })}>Sending reply</button>
  <button onClick={() => onStatusChange({ dirty: false, pending: false })}>Reply sent</button>
</div> }));

const workspace: WorkspaceSummary = { workspaceId: 4, name: 'Reading room', userCount: 2, collectionCount: 3, itemCount: 50, imageCount: 8, createdAt: '2026-01-01' };
const account: UserSummary = { userId: 7, email: 'reader@example.com', workspaceId: 4, workspaceName: 'Reading room', identityProvider: 'Microsoft', isSystemAdministrator: false, createdAt: '2026-01-01' };
const template = createMockItemTemplate({ name: 'Book', isSystem: true, description: 'Reading', properties: [{ category: 'Details', name: 'Author' }] });
const logout = vi.fn();
const refetch = vi.fn();

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(useUser).mockReturnValue({ user: createMockCurrentUser({ isSystemAdministrator: true }), loading: false, error: null, signedOut: false, refetch, logout });
  refetch.mockResolvedValue(undefined);
  vi.mocked(adminApi.getWorkspaces).mockResolvedValue([workspace]);
  vi.mocked(adminApi.getUsers).mockResolvedValue([account]);
  vi.mocked(adminApi.getSystemTemplates).mockResolvedValue([template]);
  vi.mocked(adminApi.createSystemTemplate).mockResolvedValue(template);
  vi.mocked(adminApi.updateSystemTemplate).mockResolvedValue(template);
  vi.mocked(adminApi.deleteWorkspace).mockResolvedValue(undefined);
  vi.mocked(adminApi.deleteUser).mockResolvedValue(undefined);
  vi.mocked(adminApi.deleteSystemTemplate).mockResolvedValue(undefined);
  vi.mocked(adminApi.setAdminStatus).mockResolvedValue({ ...account, isSystemAdministrator: true });
  logout.mockResolvedValue(undefined);
  vi.spyOn(window, 'confirm').mockReturnValue(true);
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function show(managed = true, extra?: ReactNode) {
  const router = createMemoryRouter([
    { path: '/admin', element: <SystemAdmin /> }, { path: '/', element: <h1>Home</h1> },
  ], { initialEntries: ['/', '/admin'], initialIndex: 1 });
  const app = <RouterProvider router={router} />;
  return { router, ...render(managed ? <SessionChangesProvider>{extra}{app}</SessionChangesProvider> : app) };
}
async function openTemplates() {
  await userEvent.click(screen.getByRole('button', { name: 'System Templates' }));
  await screen.findByRole('button', { name: 'Edit template Book' });
}

it('waits for authorization before requesting admin data', async () => {
  const userState = { user: createMockCurrentUser({ isSystemAdministrator: true }), loading: true, error: null, signedOut: false, refetch: vi.fn(), logout };
  vi.mocked(useUser).mockReturnValue(userState);
  const { unmount } = show();
  expect(screen.getByRole('status')).toHaveTextContent('Checking administrator access');
  expect(adminApi.getWorkspaces).not.toHaveBeenCalled();
  unmount();
  vi.mocked(useUser).mockReturnValue({ ...userState, loading: false });
  show();
  expect(await screen.findByRole('table', { name: '1 workspaces' })).toBeInTheDocument();
});

it.each([null, createMockCurrentUser({ isSystemAdministrator: false })])('redirects unauthorized users without loading any admin panel', async user => {
  vi.mocked(useUser).mockReturnValue({ user, loading: false, error: null, signedOut: false, refetch: vi.fn(), logout });
  show();
  expect(await screen.findByRole('heading', { name: 'Home' })).toBeInTheDocument();
  expect(adminApi.getWorkspaces).not.toHaveBeenCalled();
});

it('renders usage, identifies the selected section and supports returning to the app', async () => {
  show();
  const table = await screen.findByRole('table', { name: '1 workspaces' });
  expect(table).toHaveTextContent('Reading room');
  expect(table).toHaveTextContent('50');
  expect(screen.getByRole('region', { name: 'Workspace usage' })).toHaveAttribute('tabindex', '0');
  expect(screen.getByRole('button', { name: 'Workspaces' })).toHaveAttribute('aria-pressed', 'true');
  await userEvent.click(screen.getByRole('button', { name: 'Workspaces' }));
  expect(adminApi.getWorkspaces).toHaveBeenCalledOnce();
  await userEvent.click(screen.getByRole('button', { name: '← Back to App' }));
  expect(await screen.findByRole('heading', { name: 'Home' })).toBeInTheDocument();
});

it('cancels abandoned tabs and keeps a late workspace failure out of the selected section', async () => {
  const pending = deferred<WorkspaceSummary[]>();
  vi.mocked(adminApi.getWorkspaces).mockReturnValue(pending.promise);
  show();
  const signal = vi.mocked(adminApi.getWorkspaces).mock.calls[0][0]!.signal!;
  await userEvent.click(screen.getByRole('button', { name: 'Support' }));
  expect(signal.aborted).toBe(true);
  await act(async () => pending.reject(new Error('Late failure')));
  expect(screen.getByText('Support workflow')).toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('offers recovery for failed loads and distinguishes a successfully empty list', async () => {
  vi.mocked(adminApi.getWorkspaces).mockRejectedValueOnce(new Error('Offline')).mockResolvedValue([]);
  show();
  expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load workspaces');
  expect(screen.queryByText('No workspaces found')).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
  expect(await screen.findByText('No workspaces found')).toBeInTheDocument();
});

it('confirms workspace deletion, blocks duplicates and retains a failed action for retry', async () => {
  const pending = deferred<void>();
  vi.mocked(adminApi.deleteWorkspace).mockReturnValueOnce(pending.promise);
  show();
  const remove = await screen.findByRole('button', { name: 'Delete workspace Reading room' });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await userEvent.click(remove);
  expect(adminApi.deleteWorkspace).not.toHaveBeenCalled();
  await userEvent.click(remove);
  expect(remove).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Users' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Sign Out' })).toBeDisabled();
  await act(async () => pending.reject(new Error('Deletion failed')));
  expect(await screen.findByRole('alert')).toHaveTextContent('Deletion failed');
  vi.mocked(adminApi.getWorkspaces).mockResolvedValue([]);
  await userEvent.click(remove);
  expect(await screen.findByText('No workspaces found')).toBeInTheDocument();
  expect(adminApi.deleteWorkspace).toHaveBeenLastCalledWith(4);
  expect(refetch).toHaveBeenCalledTimes(2);
  expect(refetch).toHaveBeenLastCalledWith({ throwOnError: true });
});

it('recovers an uncertain workspace deletion with a session read and never repeats the deletion', async () => {
  vi.mocked(adminApi.deleteWorkspace).mockRejectedValue(new Error('Deletion response lost'));
  refetch.mockRejectedValueOnce(new Error('Session unavailable')).mockResolvedValue(undefined);
  show();
  await userEvent.click(await screen.findByRole('button', { name: 'Delete workspace Reading room' }));
  expect(await screen.findByRole('dialog')).toHaveTextContent('Session unavailable');
  expect(screen.getByRole('button', { name: 'Users' })).toBeDisabled();
  await userEvent.click(screen.getByRole('button', { name: 'Retry session refresh' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(adminApi.deleteWorkspace).toHaveBeenCalledOnce();
  expect(refetch).toHaveBeenCalledTimes(2);
  expect(screen.getByRole('button', { name: 'Users' })).toBeEnabled();
});

it('allows another registered editor to cancel the session change before workspace deletion', async () => {
  function OtherEditor() { useEditorStatus(true, false); return null; }
  show(true, <OtherEditor />);
  vi.mocked(window.confirm).mockReturnValueOnce(true).mockReturnValueOnce(false);
  await userEvent.click(await screen.findByRole('button', { name: 'Delete workspace Reading room' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Workspace deletion cancelled');
  expect(adminApi.deleteWorkspace).not.toHaveBeenCalled();
  expect(refetch).not.toHaveBeenCalled();
});

it('accepts partial email searches, repeats the active search and clears it', async () => {
  show();
  await userEvent.click(screen.getByRole('button', { name: 'Users' }));
  await screen.findByRole('table', { name: '1 users' });
  const search = screen.getByRole('searchbox', { name: 'Email contains' });
  await userEvent.type(search, ' reader ');
  expect(adminApi.getUsers).toHaveBeenCalledOnce();
  await userEvent.click(screen.getByRole('button', { name: 'Search' }));
  await screen.findByRole('table', { name: '1 users' });
  expect(adminApi.getUsers).toHaveBeenLastCalledWith('reader', { signal: expect.any(AbortSignal) });
  await userEvent.click(screen.getByRole('button', { name: 'Search' }));
  await screen.findByRole('table', { name: '1 users' });
  expect(adminApi.getUsers).toHaveBeenCalledTimes(3);
  await userEvent.clear(search);
  expect(screen.getByRole('button', { name: 'Clear' })).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Clear' }));
  await screen.findByRole('table', { name: '1 users' });
  expect(adminApi.getUsers).toHaveBeenLastCalledWith(undefined, { signal: expect.any(AbortSignal) });
  expect(screen.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument();
});

it('uses labeled admin controls and reloads after granting and revoking access', async () => {
  const pending = deferred<UserSummary>();
  vi.mocked(adminApi.getUsers).mockResolvedValueOnce([{ ...account, workspaceName: '' }]).mockResolvedValue([{ ...account, isSystemAdministrator: true }]);
  vi.mocked(adminApi.setAdminStatus).mockReturnValueOnce(pending.promise);
  show();
  await userEvent.click(screen.getByRole('button', { name: 'Users' }));
  const toggle = await screen.findByRole('checkbox', { name: 'System administrator for reader@example.com' });
  expect(screen.getByRole('table')).toHaveTextContent('—');
  // The surrounding label is part of the touch target, not just the small checkbox glyph.
  await userEvent.click(toggle.closest('label')!);
  expect(toggle).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Delete user reader@example.com' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Workspaces' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Sign Out' })).toBeDisabled();
  await act(async () => pending.resolve({ ...account, isSystemAdministrator: true }));
  const granted = await screen.findByRole('checkbox', { name: 'System administrator for reader@example.com' });
  expect(granted).toBeChecked();
  await userEvent.click(granted);
  await waitFor(() => expect(adminApi.setAdminStatus).toHaveBeenLastCalledWith(7, false));
});

it('confirms account deletion and renders empty user results', async () => {
  show();
  await userEvent.click(screen.getByRole('button', { name: 'Users' }));
  const remove = await screen.findByRole('button', { name: 'Delete user reader@example.com' });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await userEvent.click(remove);
  expect(adminApi.deleteUser).not.toHaveBeenCalled();
  vi.mocked(adminApi.getUsers).mockResolvedValue([]);
  await userEvent.click(remove);
  expect(await screen.findByText('No users found')).toBeInTheDocument();
  expect(adminApi.deleteUser).toHaveBeenCalledWith(7);
});

it('reloads users after a lost deletion response without repeating the deletion', async () => {
  vi.mocked(adminApi.deleteUser).mockRejectedValue(new Error('Deletion response lost'));
  show();
  await userEvent.click(screen.getByRole('button', { name: 'Users' }));
  await userEvent.click(await screen.findByRole('button', { name: 'Delete user reader@example.com' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Action needs review');
  const read = deferred<UserSummary[]>();
  vi.mocked(adminApi.getUsers).mockReturnValue(read.promise);
  await userEvent.click(screen.getByRole('button', { name: 'Reload users' }));
  expect(screen.getByRole('button', { name: 'Reload users' })).toBeDisabled();
  await act(async () => read.resolve([]));
  expect(await screen.findByText('No users found')).toBeInTheDocument();
  expect(adminApi.deleteUser).toHaveBeenCalledOnce();
  expect(refetch).toHaveBeenCalledOnce();
  expect(adminApi.getUsers).toHaveBeenCalledTimes(2);
});

it('can enable a stale self row without asking to remove its access', async () => {
  vi.mocked(useUser).mockReturnValue({ user: createMockCurrentUser({ userId: 7, isSystemAdministrator: true }),
    loading: false, error: null, signedOut: false, refetch, logout });
  show();
  await userEvent.click(screen.getByRole('button', { name: 'Users' }));
  await userEvent.click(await screen.findByRole('checkbox', { name: 'System administrator for reader@example.com' }));
  await waitFor(() => expect(adminApi.setAdminStatus).toHaveBeenCalledExactlyOnceWith(7, true));
  expect(window.confirm).not.toHaveBeenCalled();
});

it('creates system templates using the shared labeled form and retains incomplete properties for correction', async () => {
  show();
  await openTemplates();
  await userEvent.click(screen.getByRole('button', { name: '+ New Template' }));
  expect(screen.getByRole('heading', { name: 'Create System Template' })).toBeInTheDocument();
  expect(screen.getByText('System templates are available across all workspaces.')).toBeInTheDocument();
  await userEvent.type(screen.getByRole('textbox', { name: 'Template Name' }), ' Shared book ');
  await userEvent.type(screen.getByLabelText('Description'), ' Reading ');
  await userEvent.click(screen.getByRole('button', { name: '+ Add Property' }));
  await userEvent.type(screen.getByRole('textbox', { name: 'Property category' }), 'Details');
  await userEvent.click(screen.getByRole('button', { name: 'Create Template' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('All properties must have a category and name');
  expect(adminApi.createSystemTemplate).not.toHaveBeenCalled();
  await userEvent.type(screen.getByRole('textbox', { name: 'Property name' }), 'Author');
  await userEvent.click(screen.getByRole('button', { name: 'Create Template' }));
  await screen.findByRole('button', { name: 'Edit template Book' });
  expect(adminApi.createSystemTemplate).toHaveBeenCalledWith({ name: 'Shared book', description: 'Reading', properties: [{ category: 'Details', name: 'Author' }] });
});

it('edits system templates in place and freezes a pending save', async () => {
  const pending = deferred<ItemTemplate>();
  vi.mocked(adminApi.updateSystemTemplate).mockReturnValueOnce(pending.promise);
  const { router } = show();
  await openTemplates();
  await userEvent.click(screen.getByRole('button', { name: 'Edit template Book' }));
  expect(screen.getByRole('heading', { name: 'Edit: Book' })).toBeInTheDocument();
  fireEvent.change(screen.getByRole('textbox', { name: 'Template Name' }), { target: { value: 'Updated book' } });
  fireEvent.submit(screen.getByRole('form'));
  fireEvent.submit(screen.getByRole('form'));
  expect(adminApi.updateSystemTemplate).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('textbox', { name: 'Template Name' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Users' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Sign Out' })).toBeDisabled();
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/admin');
  expect(window.confirm).not.toHaveBeenCalled();
  await act(async () => pending.reject(new Error('Save failed')));
  expect(await screen.findByRole('alert')).toHaveTextContent('Save failed');
  expect(screen.getByRole('textbox', { name: 'Template Name' })).toHaveValue('Updated book');
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
  await screen.findByRole('button', { name: 'Edit template Book' });
  expect(adminApi.updateSystemTemplate).toHaveBeenLastCalledWith(template.itemTemplateId, expect.objectContaining({ name: 'Updated book' }));
  expect(adminApi.createSystemTemplate).not.toHaveBeenCalled();
});

it('protects unsaved drafts on cancellation and section navigation, then resets them when discarded', async () => {
  show();
  await openTemplates();
  await userEvent.click(screen.getByRole('button', { name: '+ New Template' }));
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(window.confirm).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole('button', { name: 'Edit template Book' }));
  fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Draft' } });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(screen.getByLabelText('Description')).toHaveValue('Draft');
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await userEvent.click(screen.getByRole('button', { name: 'Users' }));
  expect(screen.getByRole('form')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'System Templates' }));
  expect(window.confirm).toHaveBeenCalledTimes(2);
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  await userEvent.click(screen.getByRole('button', { name: 'Edit template Book' }));
  fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Another draft' } });
  await userEvent.click(screen.getByRole('button', { name: 'Users' }));
  await screen.findByRole('table', { name: '1 users' });
  await openTemplates();
  await userEvent.click(screen.getByRole('button', { name: 'Edit template Book' }));
  expect(screen.getByLabelText('Description')).toHaveValue('Reading');
});

it('confirms template deletion and keeps all template actions disabled while deleting', async () => {
  const pending = deferred<void>();
  vi.mocked(adminApi.getSystemTemplates).mockResolvedValue([{ ...template, description: '' }]);
  vi.mocked(adminApi.deleteSystemTemplate).mockReturnValueOnce(pending.promise);
  show();
  await openTemplates();
  expect(screen.getByRole('table')).toHaveTextContent('—');
  const remove = screen.getByRole('button', { name: 'Delete template Book' });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await userEvent.click(remove);
  expect(adminApi.deleteSystemTemplate).not.toHaveBeenCalled();
  await userEvent.click(remove);
  expect(screen.getByRole('button', { name: 'Edit template Book' })).toBeDisabled();
  expect(screen.getByRole('button', { name: '+ New Template' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Sign Out' })).toBeDisabled();
  vi.mocked(adminApi.getSystemTemplates).mockResolvedValue([]);
  await act(async () => pending.resolve());
  expect(await screen.findByText('No system templates found')).toBeInTheDocument();
});

it('reports failed sign-out, serializes a retry and returns to the landing page on success', async () => {
  const pending = deferred<void>();
  logout.mockRejectedValueOnce(new Error('Offline')).mockReturnValueOnce(pending.promise);
  const assign = vi.fn();
  vi.stubGlobal('location', { ...window.location, assign });
  show();
  await userEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Unable to sign out');
  await userEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
  expect(screen.getByRole('button', { name: 'Signing out…' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Users' })).toBeDisabled();
  await act(async () => pending.resolve());
  expect(assign).toHaveBeenCalledWith('/');
  expect(logout).toHaveBeenCalledTimes(2);
});

it('protects unsent support replies and blocks section navigation and sign-out during support mutations', async () => {
  show();
  await userEvent.click(screen.getByRole('button', { name: 'Support' }));
  await userEvent.click(screen.getByRole('button', { name: 'Draft reply' }));
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await userEvent.click(screen.getByRole('button', { name: 'Workspaces' }));
  expect(screen.getByText('Support workflow')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Sending reply' }));
  for (const name of ['Workspaces', 'Users', 'System Templates', 'Support', '← Back to App', 'Sign Out']) {
    expect(screen.getByRole('button', { name })).toBeDisabled();
  }
  await userEvent.click(screen.getByRole('button', { name: 'Reply sent' }));
  await userEvent.click(screen.getByRole('button', { name: 'Workspaces' }));
  expect(await screen.findByRole('table', { name: '1 workspaces' })).toBeInTheDocument();
  expect(window.confirm).toHaveBeenCalledTimes(1);
});

it('protects system drafts on browser history and confirms sign-out once before changing the session', async () => {
  const assign = vi.fn();
  vi.stubGlobal('location', { ...window.location, assign });
  const { router } = show();
  await openTemplates();
  await userEvent.click(screen.getByRole('button', { name: 'Edit template Book' }));
  fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Retain this draft' } });
  vi.mocked(window.confirm).mockReturnValue(false);
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/admin');
  await userEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
  expect(logout).not.toHaveBeenCalled();
  expect(screen.getByLabelText('Description')).toHaveValue('Retain this draft');
  vi.mocked(window.confirm).mockClear().mockReturnValue(true);
  await userEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
  expect(window.confirm).toHaveBeenCalledOnce();
  expect(logout).toHaveBeenCalledOnce();
  expect(assign).toHaveBeenCalledExactlyOnceWith('/');
  expect(refetch).not.toHaveBeenCalled();
  const unload = new Event('beforeunload', { cancelable: true });
  window.dispatchEvent(unload);
  expect(unload.defaultPrevented).toBe(false);
});

it.each([true, false])('recovers an uncertain administrator sign-out using a session read only (shared=%s)', async managed => {
  logout.mockRejectedValue(new Error('Sign-out response lost'));
  refetch.mockRejectedValueOnce(new Error('Session unavailable')).mockResolvedValue(undefined);
  show(managed);
  await userEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Session unavailable');
  expect(screen.getByRole('button', { name: 'Users' })).toBeDisabled();
  await userEvent.click(screen.getByRole('button', { name: 'Retry session refresh' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Sign-out response lost');
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(logout).toHaveBeenCalledOnce();
  expect(refetch).toHaveBeenCalledTimes(2);
  expect(refetch).toHaveBeenLastCalledWith({ throwOnError: true });
  expect(screen.getByRole('button', { name: 'Users' })).toBeEnabled();
});
