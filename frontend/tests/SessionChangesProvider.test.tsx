import { StrictMode, useLayoutEffect, useState } from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import { UserProvider } from '../src/contexts/UserContext';
import { WorkspaceSession } from '../src/contexts/WorkspaceSession';
import { SessionChangesProvider } from '../src/contexts/SessionChangesProvider';
import { useSessionChanges } from '../src/data/auth/useSessionChanges';
import { useEditorStatus } from '../src/data/shared/useEditorStatus';
import { useUnsavedNavigation } from '../src/data/shared/useUnsavedNavigation';
import WorkspaceSwitcher from '../src/components/common/WorkspaceSwitcher';
import UserButton from '../src/components/user/UserButton';
import { useUser } from '../src/contexts/useUser';
import { authApi, workspacesApi } from '../src/api';
import { createMockCurrentUser, createMockWorkspaceMembership } from './testUtils/factories';
import { deferred } from './testUtils/deferred';

const firstWorkspace = createMockWorkspaceMembership({ workspaceId: 1, workspaceName: 'First workspace' });
const secondWorkspace = createMockWorkspaceMembership({ workspaceId: 2, workspaceName: 'Second workspace' });
const first = createMockCurrentUser({ activeWorkspace: firstWorkspace, workspaces: [firstWorkspace, secondWorkspace] });
const second = { ...first, activeWorkspace: secondWorkspace };
beforeEach(() => {
  vi.spyOn(authApi, 'getCurrentUser').mockResolvedValue(first);
  vi.spyOn(authApi, 'logout').mockResolvedValue(undefined);
  vi.spyOn(workspacesApi, 'switch').mockResolvedValue({ success: true, workspaceId: 2, workspaceName: 'Second workspace' });
  vi.spyOn(window, 'confirm').mockReturnValue(false);
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function Draft() {
  const [text, setText] = useState('');
  const [pending, setPending] = useState(false);
  useEditorStatus(text !== '', pending);
  useUnsavedNavigation(text !== '', pending);
  return <><input aria-label="Draft" value={text} onChange={event => setText(event.target.value)} />
    <button onClick={() => setPending(!pending)}>Toggle pending editor</button></>;
}
function Overview() {
  const { user } = useUser();
  return <h1>{user?.activeWorkspace?.workspaceName} collections</h1>;
}
function setup() {
  const router = createMemoryRouter([
    { path: '/edit', element: <><WorkspaceSwitcher /><UserButton /><Draft /></> },
    { path: '/collections', element: <><WorkspaceSwitcher /><Overview /></> },
  ], { initialEntries: ['/edit'] });
  return { router, ...render(<StrictMode><UserProvider><WorkspaceSession navigate={router.navigate}>
    <RouterProvider router={router} />
  </WorkspaceSession></UserProvider></StrictMode>) };
}
const selectSecond = async () => userEvent.click(await screen.findByRole('button', { name: /Second workspace/, hidden: true }));

it('registers editor constraints before a parent layout action can change the session', async () => {
  const change = vi.fn();
  const refresh = vi.fn();
  const report = vi.fn();
  function Editor() {
    useEditorStatus(true, true, report);
    return <p>Saving draft</p>;
  }
  function Parent() {
    const { changes } = useSessionChanges();
    useLayoutEffect(() => { void changes.run('workspace', change, refresh, window.confirm); }, [changes]);
    return <Editor />;
  }
  const { unmount } = render(<SessionChangesProvider><Parent /></SessionChangesProvider>);
  await act(async () => {});
  expect(report).toHaveBeenLastCalledWith({ dirty: true, pending: true });
  expect(change).not.toHaveBeenCalled();
  expect(refresh).not.toHaveBeenCalled();
  expect(window.confirm).not.toHaveBeenCalled();
  unmount();
  expect(report).toHaveBeenLastCalledWith({ dirty: false, pending: false });
});

it('does not change the session after a rejected discard and allows a confirmed switch to retire old drafts', async () => {
  const { router } = setup();
  await screen.findByRole('button', { name: /Switch workspace: First workspace/ });
  fireEvent.change(screen.getByLabelText('Draft'), { target: { value: 'Keep this' } });
  await selectSecond();
  expect(authApi.getCurrentUser).toHaveBeenCalledTimes(1);
  expect(workspacesApi.switch).not.toHaveBeenCalled();
  expect(screen.getByLabelText('Draft')).toHaveValue('Keep this');
  vi.mocked(window.confirm).mockReturnValue(true);
  vi.mocked(authApi.getCurrentUser).mockResolvedValue(second);
  await selectSecond();
  expect(await screen.findByRole('heading', { name: 'Second workspace collections' })).toBeInTheDocument();
  expect(router.state.location.pathname).toBe('/collections');
  expect(window.confirm).toHaveBeenCalledTimes(2);
  expect(workspacesApi.switch).toHaveBeenCalledExactlyOnceWith(2);
  expect(screen.queryByLabelText('Draft')).not.toBeInTheDocument();
});

it('blocks both session actions while any editor is pending, without asking to discard', async () => {
  setup();
  await screen.findByRole('button', { name: 'Sign Out' });
  await userEvent.click(screen.getByRole('button', { name: 'Toggle pending editor' }));
  await selectSecond();
  expect(screen.getByRole('alert')).toHaveTextContent('Wait for the current action');
  await userEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
  expect(authApi.logout).not.toHaveBeenCalled();
  expect(workspacesApi.switch).not.toHaveBeenCalled();
  expect(window.confirm).not.toHaveBeenCalled();
});

it('keeps the app inert through a switch and failed read, then retries only session reconciliation', async () => {
  const { container } = setup();
  await screen.findByRole('button', { name: 'Sign Out' });
  const switching = deferred<{ success: boolean; workspaceId: number; workspaceName: string }>();
  vi.mocked(workspacesApi.switch).mockReturnValue(switching.promise);
  vi.mocked(authApi.getCurrentUser).mockRejectedValueOnce(new Error('Session check offline')).mockResolvedValue(second);
  await selectSecond();
  expect(container.querySelector('.session-change__content')).toHaveAttribute('inert');
  const dialog = screen.getByRole('dialog', { name: 'Updating your session' });
  fireEvent(dialog, new Event('cancel', { bubbles: true, cancelable: true }));
  expect(dialog).toHaveAttribute('open');
  await act(async () => switching.resolve({ success: true, workspaceId: 2, workspaceName: 'Second workspace' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Session check offline');
  expect(container.querySelector('.session-change__content')).toHaveAttribute('inert');
  await userEvent.click(screen.getByRole('button', { name: 'Retry session refresh' }));
  expect(await screen.findByRole('heading', { name: 'Second workspace collections' })).toBeInTheDocument();
  expect(container.querySelector('.session-change__content')).not.toHaveAttribute('inert');
  expect(workspacesApi.switch).toHaveBeenCalledOnce();
});

it('uses the authoritative session after a failed switch response and never repeats the write automatically', async () => {
  setup();
  await screen.findByRole('button', { name: 'Sign Out' });
  vi.mocked(workspacesApi.switch).mockRejectedValue(new Error('Response lost'));
  vi.mocked(authApi.getCurrentUser).mockResolvedValue(second);
  await selectSecond();
  expect(await screen.findByRole('heading', { name: 'Second workspace collections' })).toBeInTheDocument();
  expect(screen.getByRole('alert')).toHaveTextContent('Response lost');
  expect(workspacesApi.switch).toHaveBeenCalledOnce();
});

it('requires confirmation before header sign-out and preserves a rejected draft', async () => {
  setup();
  await screen.findByRole('button', { name: 'Sign Out' });
  fireEvent.change(screen.getByLabelText('Draft'), { target: { value: 'Keep this' } });
  await userEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
  expect(authApi.logout).not.toHaveBeenCalled();
  expect(screen.getByLabelText('Draft')).toHaveValue('Keep this');
});

it('suppresses a second browser unload warning only after successful sign-out', async () => {
  const change = vi.fn().mockRejectedValueOnce(new Error('No response')).mockResolvedValue(undefined);
  function Control() {
    const { changes } = useSessionChanges();
    useUnsavedNavigation(true, false);
    return <button onClick={() => void changes.run('logout', change, vi.fn(), () => true)}>End session</button>;
  }
  const router = createMemoryRouter([{ path: '/', element: <Control /> }]);
  render(<SessionChangesProvider><RouterProvider router={router} /></SessionChangesProvider>);
  function closing() { const event = new Event('beforeunload', { cancelable: true }); window.dispatchEvent(event); return event.defaultPrevented; }
  expect(closing()).toBe(true);
  await userEvent.click(screen.getByRole('button', { name: 'End session' }));
  expect(closing()).toBe(true);
  await userEvent.click(screen.getByRole('button', { name: 'End session' }));
  expect(closing()).toBe(false);
});
