import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import { beforeEach, expect, it, vi } from 'vitest';
import UserContext, { UserProvider, type UserContextValue } from '../src/contexts/UserContext';
import { NoWorkspaceHandler } from '../src/components/common/NoWorkspaceHandler';
import { workspacesApi, authApi } from '../src/api';
import type { RestorableWorkspace, RestoreWorkspacesResponse } from '../src/api/workspaces';
import { createMockCurrentUser } from './testUtils';
import { deferred } from './testUtils/deferred';

vi.mock('../src/api', () => ({ workspacesApi: { getRestorableWorkspaces: vi.fn(), restoreWorkspaces: vi.fn() }, authApi: { getCurrentUser: vi.fn(), logout: vi.fn() } }));
const workspaces: RestorableWorkspace[] = [1, 2].map(id => ({ workspaceId: id, name: `Study ${id}`, deletedAt: '2026-11-01', daysRemaining: 20, stats: { collectionCount: 2, itemCount: 10, categoryCount: 4, imageCount: 8 } }));
const restored = { restoredWorkspaceIds: [1, 2], activeWorkspaceId: 1 };
const refetch = vi.fn();
const session = (overrides: Partial<UserContextValue> = {}): UserContextValue => ({ user: createMockCurrentUser({ activeWorkspace: null, workspaceId: null, workspaces: [] }), loading: false, error: null, signedOut: false, refetch, logout: vi.fn(), ...overrides });
const button = (name: string) => screen.getByRole('button', { name });
const checkbox = (id: number) => screen.getByRole('checkbox', { name: new RegExp(`Study ${id}`) });
const routes = [
  { path: '/previous', element: <h1>Previous page</h1> },
  { path: '/protected', element: <NoWorkspaceHandler><h1>Protected content</h1></NoWorkspaceHandler> },
  { path: '/collections', element: <h1>Collections destination</h1> },
  { path: '/workspaces/new', element: <h1>New workspace destination</h1> },
];
function mount(value = session()) {
  const router = createMemoryRouter(routes, { initialEntries: ['/previous', '/protected'], initialIndex: 1 });
  const tree = (current: UserContextValue) => <UserContext.Provider value={current}><RouterProvider router={router} /></UserContext.Provider>;
  const result = render(tree(value));
  return { ...result, router, update: (current: UserContextValue) => result.rerender(tree(current)) };
}
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(workspacesApi.getRestorableWorkspaces).mockResolvedValue(workspaces);
  vi.mocked(workspacesApi.restoreWorkspaces).mockResolvedValue(restored);
  refetch.mockResolvedValue(undefined);
});

it('waits for identity and skips recovery reads for anonymous users and users with memberships', () => {
  const app = mount(session({ loading: true }));
  expect(screen.getByRole('status')).toHaveTextContent('Checking your workspaces');
  expect(screen.queryByText('Protected content')).not.toBeInTheDocument();
  app.update(session({ user: null }));
  expect(screen.getByText('Protected content')).toBeInTheDocument();
  app.update(session({ user: createMockCurrentUser() }));
  expect(screen.getByText('Protected content')).toBeInTheDocument();
  expect(workspacesApi.getRestorableWorkspaces).not.toHaveBeenCalled();
});

it('redirects only a confirmed empty recovery list and replaces the unusable history entry', async () => {
  const read = deferred<RestorableWorkspace[]>();
  vi.mocked(workspacesApi.getRestorableWorkspaces).mockReturnValue(read.promise);
  const { router } = mount();
  expect(screen.getByRole('status')).toBeInTheDocument();
  expect(screen.queryByText('Protected content')).not.toBeInTheDocument();
  await act(async () => read.resolve([]));
  expect(screen.getByText('New workspace destination')).toBeInTheDocument();
  expect(workspacesApi.getRestorableWorkspaces).toHaveBeenCalledExactlyOnceWith({ signal: expect.any(AbortSignal) });
  await act(async () => { await router.navigate(-1); });
  expect(screen.getByText('Previous page')).toBeInTheDocument();
});

it('reports failed recovery checks, retries the same lookup, and uses that list without a second modal fetch', async () => {
  vi.mocked(workspacesApi.getRestorableWorkspaces).mockRejectedValueOnce(new Error('Recovery offline')).mockResolvedValue(workspaces);
  const user = userEvent.setup();
  const { router } = mount();
  expect(await screen.findByRole('alert')).toHaveTextContent('Recovery offline');
  expect(router.state.location.pathname).toBe('/protected');
  expect(screen.queryByText('Protected content')).not.toBeInTheDocument();
  await user.click(button('Try again'));
  expect(await screen.findByRole('dialog', { name: 'Restore workspace' })).toBeInTheDocument();
  expect(workspacesApi.getRestorableWorkspaces).toHaveBeenCalledTimes(2);
  expect(checkbox(1)).toBeChecked();
  expect(checkbox(2)).not.toBeChecked();
  await user.click(button('Create a new workspace'));
  expect(screen.getByText('New workspace destination')).toBeInTheDocument();
  expect(workspacesApi.restoreWorkspaces).not.toHaveBeenCalled();
});

it('allows an explicit creation choice after a failed check without treating failure as an empty list', async () => {
  vi.mocked(workspacesApi.getRestorableWorkspaces).mockRejectedValue(null);
  mount();
  expect(await screen.findByRole('alert')).toHaveTextContent('An error occurred');
  fireEvent.click(button('Create a new workspace'));
  expect(screen.getByText('New workspace destination')).toBeInTheDocument();
});

it('cancels old identity checks and ignores late results when memberships arrive', async () => {
  const first = deferred<RestorableWorkspace[]>();
  const second = deferred<RestorableWorkspace[]>();
  vi.mocked(workspacesApi.getRestorableWorkspaces).mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
  const app = mount();
  const firstSignal = vi.mocked(workspacesApi.getRestorableWorkspaces).mock.calls[0][0]!.signal!;
  app.update(session({ user: createMockCurrentUser({ userId: 2, workspaces: [] }) }));
  const secondSignal = vi.mocked(workspacesApi.getRestorableWorkspaces).mock.calls[1][0]!.signal!;
  expect(firstSignal.aborted).toBe(true);
  await act(async () => first.resolve([]));
  expect(app.router.state.location.pathname).toBe('/protected');
  app.update(session({ user: createMockCurrentUser({ userId: 2 }) }));
  expect(secondSignal.aborted).toBe(true);
  await act(async () => second.reject(new Error('Old failure')));
  expect(screen.getByText('Protected content')).toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('serializes restoration, locks every control, and retries only refresh after a confirmed restore', async () => {
  const write = deferred<RestoreWorkspacesResponse>();
  const refresh = deferred<void>();
  vi.mocked(workspacesApi.restoreWorkspaces).mockReturnValue(write.promise);
  refetch.mockRejectedValueOnce(new Error('Session unavailable')).mockReturnValueOnce(refresh.promise);
  const user = userEvent.setup();
  const { router } = mount();
  const dialog = await screen.findByRole('dialog');
  fireEvent(dialog, new Event('cancel', { cancelable: true }));
  fireEvent.click(dialog);
  expect(dialog).toHaveAttribute('open');
  await user.click(checkbox(1));
  expect(button('Restore selected workspaces')).toBeDisabled();
  await user.click(checkbox(1));
  await user.click(checkbox(2));
  await user.dblClick(button('Restore selected workspaces'));
  expect(workspacesApi.restoreWorkspaces).toHaveBeenCalledExactlyOnceWith({ workspaceIds: [1, 2] });
  expect(button('Restoring…')).toBeDisabled();
  expect(button('Create a new workspace')).toBeDisabled();
  for (const check of screen.getAllByRole('checkbox')) expect(check).toBeDisabled();
  expect(refetch).not.toHaveBeenCalled();
  await act(async () => write.resolve(restored));
  expect(screen.getByRole('alert')).toHaveTextContent('Session unavailable');
  expect(router.state.location.pathname).toBe('/protected');
  expect(refetch).toHaveBeenCalledWith({ throwOnError: true });
  expect(checkbox(1)).toBeDisabled();
  expect(screen.queryByText('Reload recovery list')).not.toBeInTheDocument();
  await user.click(button('Continue to workspace'));
  expect(button('Refreshing session…')).toBeDisabled();
  await act(async () => refresh.resolve());
  expect(screen.getByText('Collections destination')).toBeInTheDocument();
  expect(workspacesApi.restoreWorkspaces).toHaveBeenCalledOnce();
  expect(refetch).toHaveBeenCalledTimes(2);
  await act(async () => { await router.navigate(-1); });
  expect(screen.getByText('Previous page')).toBeInTheDocument();
});

it('retains a failed selection, reloads availability, and refuses an empty restore response', async () => {
  vi.mocked(workspacesApi.restoreWorkspaces).mockRejectedValueOnce(null).mockResolvedValueOnce({ restoredWorkspaceIds: [], activeWorkspaceId: 0 });
  const user = userEvent.setup();
  mount();
  await screen.findByRole('dialog');
  await user.click(checkbox(2));
  await user.click(checkbox(1));
  await user.click(button('Restore selected workspaces'));
  expect(await screen.findByRole('alert')).toHaveTextContent('Unable to restore workspaces');
  expect(checkbox(2)).toBeChecked();
  vi.mocked(workspacesApi.getRestorableWorkspaces).mockResolvedValue([workspaces[0]]);
  await user.click(button('Reload recovery list'));
  await screen.findByRole('dialog');
  expect(button('Restore selected workspaces')).toBeDisabled();
  expect(checkbox(1)).not.toBeChecked();
  await user.click(checkbox(1));
  await user.click(button('Restore selected workspaces'));
  expect(await screen.findByRole('alert')).toHaveTextContent('No workspace was restored');
  expect(refetch).not.toHaveBeenCalled();
  expect(checkbox(1)).toBeEnabled();
});

it('finishes navigation when the actual session provider adds memberships during the required refresh', async () => {
  vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce(createMockCurrentUser({ activeWorkspace: null, workspaceId: null, workspaces: [] })).mockResolvedValue(createMockCurrentUser());
  const router = createMemoryRouter(routes, { initialEntries: ['/protected'] });
  render(<UserProvider><RouterProvider router={router} /></UserProvider>);
  await screen.findByRole('dialog');
  fireEvent.click(button('Restore selected workspaces'));
  expect(await screen.findByText('Collections destination')).toBeInTheDocument();
  expect(authApi.getCurrentUser).toHaveBeenCalledTimes(2);
  expect(workspacesApi.getRestorableWorkspaces).toHaveBeenCalledOnce();
});

it('does not navigate for an old user when a restore settles after identity changes', async () => {
  const write = deferred<RestoreWorkspacesResponse>();
  vi.mocked(workspacesApi.restoreWorkspaces).mockReturnValue(write.promise);
  const app = mount();
  await screen.findByRole('dialog');
  fireEvent.click(button('Restore selected workspaces'));
  app.update(session({ user: createMockCurrentUser({ userId: 2 }) }));
  await act(async () => write.resolve(restored));
  expect(screen.getByText('Protected content')).toBeInTheDocument();
  expect(app.router.state.location.pathname).toBe('/protected');
});

it('aborts the recovery read when leaving the route', async () => {
  const read = deferred<RestorableWorkspace[]>();
  vi.mocked(workspacesApi.getRestorableWorkspaces).mockReturnValue(read.promise);
  const app = mount();
  const signal = vi.mocked(workspacesApi.getRestorableWorkspaces).mock.calls[0][0]!.signal!;
  await act(async () => { await app.router.navigate('/previous'); });
  expect(signal.aborted).toBe(true);
  await act(async () => read.resolve([]));
  await waitFor(() => expect(screen.getByText('Previous page')).toBeInTheDocument());
});
