import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import InvitationView from '../../src/views/InvitationView';
import { invitationsApi } from '../../src/api/invitations';
import { useUser } from '../../src/contexts/useUser';
import { SessionChangesContext } from '../../src/contexts/SessionChangesContext';
import { SessionChanges } from '../../src/data/auth/SessionChanges';
import { WorkspaceRole } from '../../src/utils/types';
import { createdInvitation, teamAdministrator } from '../testUtils/team';
import { deferred } from '../testUtils/deferred';

vi.mock('../../src/api/invitations', () => ({ invitationsApi: { preview: vi.fn(), accept: vi.fn() } }));
vi.mock('../../src/contexts/useUser', () => ({ useUser: vi.fn() }));
const api = vi.mocked(invitationsApi);
const created = createdInvitation();
const path = `/join/${created.invitation.invitationId}`;
const request = { invitationId: created.invitation.invitationId, token: created.token };
const preview = { workspaceName: 'Shared library', email: created.invitation.email, role: WorkspaceRole.Normal, expiresAt: created.invitation.expiresAt };
const routers: ReturnType<typeof createMemoryRouter>[] = [];
const refresh = vi.fn();
function show(url = `${path}#${created.token}`, shared?: SessionChanges) {
  const router = createMemoryRouter([
    { path: '/join/:invitationId', element: <InvitationView /> },
    { path: '/join', element: <InvitationView /> },
    { path: '/collections', element: <h1>Collections</h1> },
  ], { initialEntries: [url] });
  routers.push(router);
  const tree = <RouterProvider router={router} />;
  const rendered = render(shared ? <SessionChangesContext.Provider value={shared}>{tree}</SessionChangesContext.Provider> : tree);
  return { router, ...rendered };
}
beforeEach(() => {
  vi.resetAllMocks();
  sessionStorage.clear();
  refresh.mockResolvedValue(undefined);
  vi.mocked(useUser).mockReturnValue({ user: teamAdministrator(), loading: false, error: null, signedOut: false, logout: vi.fn(), refetch: refresh });
  api.preview.mockResolvedValue(preview);
  api.accept.mockResolvedValue(teamAdministrator());
});
afterEach(() => { routers.splice(0).forEach(router => router.dispose()); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it('preserves the private fragment in tab storage before redirecting to sign-in without it', async () => {
  const location = { href: '' };
  vi.stubGlobal('location', location);
  vi.mocked(useUser).mockReturnValue({ ...useUser(), user: null });
  const { router } = show();
  await waitFor(() => expect(location.href).toBe(`/signin?returnUrl=${encodeURIComponent(path)}`));
  expect(location.href).not.toContain(created.token);
  expect(router.state.location.hash).toBe('');
  expect(sessionStorage.getItem(`workspace-invitation:${request.invitationId}`)).toBe(created.token);
  expect(api.preview).not.toHaveBeenCalled();
});

it.each(['/join', '/join/bad-id', `${path}#incomplete`, path])('explains an incomplete link: %s', async url => {
  show(url);
  expect(await screen.findByText('This invitation link is incomplete')).toBeInTheDocument();
  expect(api.preview).not.toHaveBeenCalled();
});

it('explains unavailable storage without sending the token in a sign-in URL', async () => {
  vi.stubGlobal('sessionStorage', { getItem: vi.fn(), setItem: () => { throw new Error('Storage disabled'); } });
  show();
  expect(await screen.findByText('Unable to save this invitation')).toBeInTheDocument();
  expect(api.preview).not.toHaveBeenCalled();
});

it.each([WorkspaceRole.Normal, WorkspaceRole.WorkspaceAdmin])('reviews the destination, account and %s role before joining', async role => {
  api.preview.mockResolvedValue({ ...preview, role });
  const { router } = show();
  expect(await screen.findByRole('heading', { name: 'Join Shared library' })).toBeInTheDocument();
  expect(screen.getByText(teamAdministrator().email)).toBeInTheDocument();
  expect(screen.getByText(role === WorkspaceRole.Normal ? 'a member' : 'an admin')).toBeInTheDocument();
  expect(api.accept).not.toHaveBeenCalled();
  expect(api.preview).toHaveBeenCalledWith(request, { signal: expect.any(AbortSignal) });
  await userEvent.click(screen.getByRole('button', { name: 'Join workspace' }));
  expect(await screen.findByRole('heading', { name: 'Collections' })).toBeInTheDocument();
  expect(api.accept).toHaveBeenCalledExactlyOnceWith(request);
  expect(refresh).toHaveBeenCalledWith({ throwOnError: true });
  expect(router.state.location.pathname).toBe('/collections');
});

it('loads a saved invitation after sign-in and supports preview failure recovery and cancellation', async () => {
  sessionStorage.setItem(`workspace-invitation:${request.invitationId}`, created.token);
  api.preview.mockRejectedValueOnce(new Error('Link unavailable')).mockResolvedValue(preview);
  const { unmount } = show(path);
  expect(await screen.findByText('Invitation unavailable')).toBeInTheDocument();
  expect(screen.getByText('Link unavailable')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
  expect(await screen.findByRole('button', { name: 'Join workspace' })).toBeEnabled();
  const signal = api.preview.mock.calls[1][1]!.signal;
  unmount();
  expect(signal!.aborted).toBe(true);
});

it('announces loading and does not offer acceptance before the preview is available', async () => {
  const read = deferred<typeof preview>();
  api.preview.mockReturnValue(read.promise);
  show();
  expect(await screen.findByText('Loading invitation…')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Join workspace' })).not.toBeInTheDocument();
  await act(async () => read.resolve(preview));
  expect(screen.getByRole('button', { name: 'Join workspace' })).toBeEnabled();
});

it('reports a failed acceptance and reconciles the session before allowing an explicit retry', async () => {
  api.accept.mockRejectedValueOnce(new Error('Invitation changed'));
  show();
  await userEvent.click(await screen.findByRole('button', { name: 'Join workspace' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Invitation changed');
  expect(refresh).toHaveBeenCalledOnce();
  await userEvent.click(screen.getByRole('button', { name: 'Join workspace' }));
  expect(await screen.findByRole('heading', { name: 'Collections' })).toBeInTheDocument();
  expect(api.accept).toHaveBeenCalledTimes(2);
});

it('retries only session refresh after a confirmed grant when the session read fails', async () => {
  refresh.mockRejectedValueOnce(new Error('Session unavailable')).mockResolvedValue(undefined);
  show();
  await userEvent.click(await screen.findByRole('button', { name: 'Join workspace' }));
  expect(await screen.findByRole('dialog', { name: 'Updating your session' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Join workspace' })).toBeDisabled();
  await userEvent.click(screen.getByRole('button', { name: 'Retry session refresh' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(await screen.findByRole('heading', { name: 'Collections' })).toBeInTheDocument();
  expect(api.accept).toHaveBeenCalledOnce();
  expect(refresh).toHaveBeenCalledTimes(2);
});

it('respects shared session protection and leaves navigation unchanged when discard is cancelled', async () => {
  const shared = new SessionChanges();
  shared.protect({ dirty: true, pending: false });
  vi.spyOn(window, 'confirm').mockReturnValue(false);
  const { router } = show(undefined, shared);
  await userEvent.click(await screen.findByRole('button', { name: 'Join workspace' }));
  expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining('Discard unsaved'));
  expect(api.accept).not.toHaveBeenCalled();
  expect(router.state.location.pathname).toBe(path);
});

it('keeps acceptance disabled while another control is leaving the shared session', async () => {
  const shared = new SessionChanges();
  await shared.run('logout', async () => {}, async () => {}, () => true);
  show(undefined, shared);
  expect(await screen.findByRole('button', { name: 'Join workspace' })).toBeDisabled();
});
