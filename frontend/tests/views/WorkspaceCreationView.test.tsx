import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { createMemoryRouter, Link, RouterProvider } from 'react-router-dom';
import WorkspaceCreationView from '../../src/views/WorkspaceCreationView';
import type { EditorStatusListener } from '../../src/data/shared/useEditorStatus';

vi.mock('../../src/components/wizard/WorkspaceSetupWizard', () => ({
  default: ({ showTerms, isWelcome, onComplete, onCancel, onStatusChange }: {
    showTerms: boolean; isWelcome: boolean; onComplete: () => void; onCancel: () => void; onStatusChange: EditorStatusListener;
  }) => <div>
    <h1>Create workspace</h1>
    <p>Terms: {String(showTerms)}, welcome: {String(isWelcome)}</p>
    <button onClick={() => onStatusChange({ dirty: true, pending: false })}>Edit details</button>
    <button onClick={() => onStatusChange({ dirty: true, pending: true })}>Start save</button>
    <button onClick={onComplete}>Complete setup</button>
    <button onClick={onCancel}>Confirmed cancel</button>
    <Link to="/other">Leave setup</Link>
  </div>,
}));
let router: ReturnType<typeof createMemoryRouter>;
let destination: string;
let exitWasBlocked: boolean;
const confirm = vi.fn();
const button = (name: string) => screen.getByRole('button', { name });
function show() {
  router = createMemoryRouter([
    { path: '/workspaces/new', element: <WorkspaceCreationView /> },
    { path: '/collections', element: <h1>Collections</h1> },
    { path: '/other', element: <h1>Other page</h1> },
  ], { initialEntries: ['/workspaces/new'] });
  render(<RouterProvider router={router} />);
}
beforeEach(() => {
  vi.clearAllMocks();
  destination = '';
  exitWasBlocked = false;
  vi.spyOn(window, 'confirm').mockImplementation(confirm);
  vi.stubGlobal('location', { set href(value: string) {
    destination = value;
    const unload = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(unload);
    exitWasBlocked = unload.defaultPrevented;
  } });
});
afterEach(() => { cleanup(); router.dispose(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('renders workspace creation without welcome or terms and navigates after confirmed success', async () => {
  show();
  expect(screen.getByText('Terms: false, welcome: false')).toBeInTheDocument();
  fireEvent.click(button('Start save'));
  fireEvent.click(button('Complete setup'));
  expect(await screen.findByRole('heading', { name: 'Collections' })).toBeInTheDocument();
  expect(confirm).not.toHaveBeenCalled();
  expect(destination).toBe('');
});

it('requires confirmed discard for dirty route changes and blocks browser unload', async () => {
  confirm.mockReturnValue(false);
  show();
  fireEvent.click(button('Edit details'));
  const unload = new Event('beforeunload', { cancelable: true });
  window.dispatchEvent(unload);
  expect(unload.defaultPrevented).toBe(true);
  fireEvent.click(screen.getByRole('link', { name: 'Leave setup' }));
  expect(router.state.location.pathname).toBe('/workspaces/new');
  confirm.mockReturnValue(true);
  fireEvent.click(screen.getByRole('link', { name: 'Leave setup' }));
  expect(await screen.findByRole('heading', { name: 'Other page' })).toBeInTheDocument();
});

it('prevents route changes while setup is pending', () => {
  show();
  fireEvent.click(button('Start save'));
  fireEvent.click(screen.getByRole('link', { name: 'Leave setup' }));
  expect(router.state.location.pathname).toBe('/workspaces/new');
  expect(confirm).not.toHaveBeenCalled();
});

it('removes unload protection before a confirmed cancellation leaves for the landing page', async () => {
  show();
  fireEvent.click(button('Edit details'));
  fireEvent.click(button('Confirmed cancel'));
  await waitFor(() => expect(destination).toBe('/'));
  expect(exitWasBlocked).toBe(false);
  expect(confirm).not.toHaveBeenCalled();
});
