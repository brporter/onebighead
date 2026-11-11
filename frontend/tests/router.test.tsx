import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { createMemoryRouter, Outlet, RouterProvider, useParams } from 'react-router-dom';
import { router } from '../src/router';
import { useUser } from '../src/contexts/useUser';
import { createMockCurrentUser } from './testUtils/factories';

// Keep the real route tree and its authentication/workspace gates. Leaf views
// have their own integration suites; these doubles identify the selected page.
function RoutePage({ name }: { name: string }) {
  return <><h1>{name}</h1><output data-testid="route-params">{JSON.stringify(useParams())}</output></>;
}
vi.mock('../src/contexts/useUser', () => ({ useUser: vi.fn() }));
vi.mock('../src/App', () => ({ default: () => <main aria-label="Workspace"><Outlet /></main> }));
vi.mock('../src/views/CollectionView', () => ({ default: () => <RoutePage name="Collections" /> }));
vi.mock('../src/views/CategoryView', () => ({ default: () => <RoutePage name="Category" /> }));
vi.mock('../src/views/ItemView', () => ({ default: () => <RoutePage name="Item" /> }));
vi.mock('../src/views/InvitationView', () => ({ default: () => <RoutePage name="Invitation" /> }));
vi.mock('../src/views/SetupView', () => ({ default: () => <RoutePage name="Setup" /> }));
vi.mock('../src/views/SettingsView', () => ({ default: () => <RoutePage name="Settings" /> }));
vi.mock('../src/views/SystemAdmin', () => ({ default: () => <RoutePage name="Administration" /> }));
vi.mock('../src/views/WorkspaceCreationView', () => ({ default: () => <RoutePage name="Create workspace" /> }));
vi.mock('../src/views/TermsView', () => ({ default: () => <RoutePage name="Terms" /> }));
vi.mock('../src/views/WelcomeView', () => ({ default: () => <RoutePage name="Welcome" /> }));
vi.mock('../src/components/public/PublicLayout', () => ({ default: () => <section aria-label="Public gallery"><Outlet /></section> }));
vi.mock('../src/views/PublicCollectionsView', () => ({ default: () => <RoutePage name="Public collections" /> }));
vi.mock('../src/views/PublicCollectionDetailView', () => ({ default: () => <RoutePage name="Public collection" /> }));
vi.mock('../src/views/PublicItemView', () => ({ default: () => <RoutePage name="Public item" /> }));

const activeRouters: ReturnType<typeof createMemoryRouter>[] = [];
function show(path: string) {
  const memory = createMemoryRouter(router.routes, { initialEntries: [path] });
  activeRouters.push(memory);
  render(<RouterProvider router={memory} />);
  return memory;
}
beforeEach(() => {
  vi.mocked(useUser).mockReturnValue({ user: createMockCurrentUser(), loading: false,
    error: null, signedOut: false, refetch: vi.fn(), logout: vi.fn() });
});
afterEach(() => {
  cleanup();
  activeRouters.splice(0).forEach(memory => memory.dispose());
  vi.unstubAllGlobals();
});
afterAll(() => router.dispose());

describe('application routes', () => {
  it('announces lazy loading and redirects the workspace index to collections', async () => {
    const memory = show('/');
    expect(screen.getByRole('status')).toHaveTextContent('Loading...');
    expect(await screen.findByRole('heading', { name: 'Collections' })).toBeInTheDocument();
    expect(memory.state.location.pathname).toBe('/collections');
    expect(screen.getByRole('main', { name: 'Workspace' })).toBeInTheDocument();
  });

  it.each([
    ['/collections', 'Collections', {}],
    ['/collections/42', 'Category', { collectionId: '42' }],
    ['/collections/42/categories/8', 'Category', { collectionId: '42', categoryId: '8' }],
    ['/collections/42/items/9', 'Item', { collectionId: '42', itemId: '9' }],
    ['/setup', 'Setup', {}],
    ['/join/invitation-id', 'Invitation', { invitationId: 'invitation-id' }],
    ['/settings', 'Settings', {}],
    ['/admin', 'Administration', {}],
    ['/welcome', 'Welcome', {}],
    ['/terms', 'Terms', {}],
    ['/workspaces/new', 'Create workspace', {}],
  ])('opens %s in its intended view', async (path, heading, params) => {
    show(path);
    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument();
    expect(JSON.parse(screen.getByTestId('route-params').textContent!)).toEqual(params);
  });

  it.each([
    ['/public/books', 'Public collections', { slug: 'books' }],
    ['/public/books/collections/42', 'Public collection', { slug: 'books', collectionId: '42' }],
    ['/public/books/items/9', 'Public item', { slug: 'books', itemId: '9' }],
  ])('allows anonymous visitors to open %s', async (path, heading, params) => {
    vi.mocked(useUser).mockReturnValue({ ...useUser(), user: null });
    show(path);
    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Public gallery' })).toBeInTheDocument();
    expect(JSON.parse(screen.getByTestId('route-params').textContent!)).toEqual(params);
    expect(screen.queryByRole('main', { name: 'Workspace' })).not.toBeInTheDocument();
  });

  it('requires sign-in for private deep links and preserves the destination', () => {
    const location = { href: '' };
    vi.stubGlobal('location', location);
    vi.mocked(useUser).mockReturnValue({ ...useUser(), user: null });
    show('/collections/42/items/9?from=search');
    expect(screen.queryByRole('heading')).not.toBeInTheDocument();
    expect(location.href).toBe('/signin?returnUrl=%2Fcollections%2F42%2Fitems%2F9%3Ffrom%3Dsearch');
  });

  it.each([
    [true, false, false, '/collections', 'Welcome', '/welcome'],
    [true, true, false, '/settings', 'Terms', '/terms'],
    [true, false, false, '/workspaces/new', 'Create workspace', '/workspaces/new'],
    [true, true, false, '/welcome', 'Welcome', '/welcome'],
    [false, false, false, '/collections', 'Terms', '/terms'],
    [false, false, true, '/collections', 'Collections', '/collections'],
    [false, false, false, '/workspaces/new', 'Terms', '/terms'],
    [false, false, true, '/workspaces/new', 'Create workspace', '/workspaces/new'],
  ])('applies onboarding gates without redirect loops (admin: %s, completed: %s, accepted: %s, route: %s)', async (admin, completed, accepted, path, heading, destination) => {
    vi.mocked(useUser).mockReturnValue({ ...useUser(), user: createMockCurrentUser({
      hasCompletedWelcome: completed, hasAcceptedTerms: accepted, isWorkspaceAdmin: admin,
    }) });
    const memory = show(path);
    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument();
    expect(memory.state.location.pathname).toBe(destination);
  });
});
