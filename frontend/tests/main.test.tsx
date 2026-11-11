import { act, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import * as ReactDOM from 'react-dom/client';
import { createMemoryRouter, useLocation } from 'react-router-dom';
import { authApi, collectionsApi } from '../src/api';
import { useUser } from '../src/contexts/useUser';
import { useCollectionsData } from '../src/contexts/useData';
import { useToast } from '../src/contexts/useToast';
import { usePublish } from '../src/contexts/usePublish';
import { useSessionChanges } from '../src/data/auth/useSessionChanges';
import { createMockCollection, createMockCurrentUser } from './testUtils/factories';

vi.mock('react-dom/client', async importOriginal => {
  const actual = await importOriginal<typeof ReactDOM>();
  return { ...actual, createRoot: vi.fn(actual.createRoot) };
});

function ApplicationProbe() {
  const session = useUser();
  const collections = useCollectionsData();
  const toast = useToast();
  const publication = usePublish();
  const changes = useSessionChanges();
  const location = useLocation();
  return <>
    <h1>{session.user?.email ?? 'Checking session'}</h1>
    <output data-testid="path">{location.pathname}</output>
    <output data-testid="collection-count">{collections.collections.length}</output>
    <output data-testid="publication">{publication.pendingRequest?.action ?? 'idle'}</output>
    <output data-testid="session-coordinator">{String(changes.managed)}</output>
    <button onClick={() => { void collections.loadCollections(); }}>Load collections</button>
    <button onClick={() => toast.showToast('Application is ready')}>Notify</button>
    <button onClick={() => { void session.refetch(); }}>Refresh session</button>
  </>;
}

vi.mock('../src/router', () => ({ router: createMemoryRouter([
  { path: '*', element: <ApplicationProbe /> },
], { initialEntries: ['/collections/4'] }) }));

it('mounts the application with shared session, workspace data, publication and toast providers', async () => {
  const user = createMockCurrentUser();
  vi.spyOn(authApi, 'getCurrentUser').mockResolvedValue(user);
  const readCollections = vi.spyOn(collectionsApi, 'getAll').mockResolvedValue([createMockCollection()]);
  const container = document.createElement('div');
  container.id = 'root';
  document.body.append(container);
  const mount = vi.mocked(ReactDOM.createRoot);
  const { router } = await import('../src/router');
  try {
    await act(async () => { await import('../src/main'); });
    expect(mount).toHaveBeenCalledExactlyOnceWith(container);
    expect(await screen.findByRole('heading', { name: user.email })).toBeInTheDocument();
    expect(screen.getByTestId('path')).toHaveTextContent('/collections/4');
    expect(screen.getByTestId('session-coordinator')).toHaveTextContent('true');
    expect(screen.getByTestId('publication')).toHaveTextContent('idle');
    await userEvent.click(screen.getByRole('button', { name: 'Load collections' }));
    expect(screen.getByTestId('collection-count')).toHaveTextContent('1');
    expect(readCollections).toHaveBeenCalledOnce();
    await userEvent.click(screen.getByRole('button', { name: 'Notify' }));
    expect(screen.getByText('Application is ready').closest('[role="status"]')).toBeInTheDocument();

    // A later workspace change must retire cached data and redirect via the
    // actual navigation callback connected by the entry point.
    vi.mocked(authApi.getCurrentUser).mockResolvedValue(createMockCurrentUser({
      activeWorkspace: { ...user.activeWorkspace!, workspaceId: 2 },
    }));
    await userEvent.click(screen.getByRole('button', { name: 'Refresh session' }));
    await waitFor(() => expect(screen.getByTestId('path')).toHaveTextContent('/collections'));
    expect(router.state.location.pathname).toBe('/collections');
    expect(screen.getByTestId('collection-count')).toHaveTextContent('0');
    expect(screen.queryByText('Application is ready')).not.toBeInTheDocument();
  } finally {
    const root = mount.mock.results[0]?.value as ReactDOM.Root | undefined;
    await act(async () => root?.unmount());
    router.dispose();
    container.remove();
    vi.restoreAllMocks();
  }
});
