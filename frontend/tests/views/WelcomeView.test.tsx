import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { createMemoryRouter, Link, RouterProvider } from 'react-router-dom';
import WelcomeView from '../../src/views/WelcomeView';
import UserContext, { type UserContextValue } from '../../src/contexts/UserContext';
import type { EditorStatusListener } from '../../src/data/shared/useEditorStatus';
import { createMockCurrentUser } from '../testUtils';

vi.mock('../../src/components/wizard/WelcomeWizard', () => ({
  default: ({ onComplete, onSkip, onStatusChange }: {
    onComplete: (id: number | null) => void; onSkip: () => void; onStatusChange: EditorStatusListener;
  }) => <div>
    <h1>Welcome wizard</h1>
    <button onClick={() => onStatusChange({ dirty: true, pending: false })}>Edit details</button>
    <button onClick={() => onStatusChange({ dirty: true, pending: true })}>Start save</button>
    <button onClick={() => onComplete(123)}>Complete Setup</button>
    <button onClick={onSkip}>Skip Setup</button>
    <button onClick={() => onComplete(null)}>Recover completed welcome</button>
    <Link to="/other">Leave setup</Link>
  </div>,
}));
let router: ReturnType<typeof createMemoryRouter>;
let session: UserContextValue;
const confirm = vi.fn();
const button = (name: string) => screen.getByRole('button', { name });
function show() {
  router = createMemoryRouter([
    { path: '/welcome', element: <WelcomeView /> },
    { path: '/collections/:id', element: <h1>Created collection</h1> },
    { path: '/collections', element: <h1>Collections</h1> },
    { path: '/other', element: <h1>Other page</h1> },
  ], { initialEntries: ['/welcome'] });
  return render(<UserContext value={session}><RouterProvider router={router} /></UserContext>);
}
beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(window, 'confirm').mockImplementation(confirm);
  session = { user: createMockCurrentUser({ isWorkspaceAdmin: true }), loading: false,
    signedOut: false, error: null, refetch: vi.fn(), logout: vi.fn() };
});
afterEach(() => { cleanup(); router.dispose(); vi.restoreAllMocks(); });

it.each([false, null])('redirects a direct welcome visit without administrator access (%s)', admin => {
  session = { ...session, user: admin === null ? null : createMockCurrentUser({ isWorkspaceAdmin: admin }) };
  show();
  expect(screen.getByRole('heading', { name: 'Collections' })).toBeInTheDocument();
});

it.each([['Complete Setup', '/collections/123'], ['Skip Setup', '/collections'], ['Recover completed welcome', '/collections']])('allows intentional %s navigation while the wizard still reports saving', async (action, destination) => {
  show();
  fireEvent.click(button('Start save'));
  fireEvent.click(button(action));
  await waitFor(() => expect(router.state.location.pathname).toBe(destination));
  expect(confirm).not.toHaveBeenCalled();
  const unload = new Event('beforeunload', { cancelable: true });
  window.dispatchEvent(unload);
  expect(unload.defaultPrevented).toBe(false);
});

it('protects dirty details during route changes and browser unload, then honors confirmed discard', async () => {
  confirm.mockReturnValue(false);
  show();
  expect(screen.getByRole('heading', { name: 'Welcome wizard' })).toBeInTheDocument();
  fireEvent.click(button('Edit details'));
  const unload = new Event('beforeunload', { cancelable: true });
  window.dispatchEvent(unload);
  expect(unload.defaultPrevented).toBe(true);
  fireEvent.click(screen.getByRole('link', { name: 'Leave setup' }));
  expect(router.state.location.pathname).toBe('/welcome');
  expect(confirm).toHaveBeenCalledOnce();
  confirm.mockReturnValue(true);
  fireEvent.click(screen.getByRole('link', { name: 'Leave setup' }));
  expect(await screen.findByRole('heading', { name: 'Other page' })).toBeInTheDocument();
});

it('blocks pending navigation but retires the wizard when administrator access is lost', async () => {
  const view = show();
  fireEvent.click(button('Start save'));
  fireEvent.click(screen.getByRole('link', { name: 'Leave setup' }));
  expect(router.state.location.pathname).toBe('/welcome');
  expect(confirm).not.toHaveBeenCalled();
  session = { ...session, user: createMockCurrentUser({ isWorkspaceAdmin: false }) };
  view.rerender(<UserContext value={session}><RouterProvider router={router} /></UserContext>);
  expect(await screen.findByRole('heading', { name: 'Collections' })).toBeInTheDocument();
  expect(confirm).not.toHaveBeenCalled();
});
