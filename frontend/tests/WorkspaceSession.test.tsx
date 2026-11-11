import { StrictMode, useEffect, useState, type ReactNode } from 'react';
import { act, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { WorkspaceSession } from '../src/contexts/WorkspaceSession';
import UserContext, { type UserContextValue } from '../src/contexts/UserContext';
import { DataProvider } from '../src/contexts/DataContext';
import type { DataContextValue } from './testUtils/dataTypes';
import * as hooks from '../src/contexts/useData';
import { useUser } from '../src/contexts/useUser';
import { useToast } from '../src/contexts/useToast';
import { useData } from './testUtils/useData';
import { collectionsApi, categoriesApi, itemsApi, templatesApi, suggestionsApi, themesApi, workspacesApi } from '../src/api';
import WorkspaceSetupWizard from '../src/components/wizard/WorkspaceSetupWizard';
import { createMockCategory, createMockCollection, createMockCollectionTheme, createMockCurrentUser,
  createMockItem, createMockItemTemplate, createMockWorkspaceMembership } from './testUtils/factories';
import { deferred } from './testUtils/deferred';
import type { CurrentUser } from '../src/utils/types';
import { WorkspaceRole } from '../src/utils/types';

const first = createMockCurrentUser();
const second = createMockCurrentUser({ activeWorkspace: createMockWorkspaceMembership({ workspaceId: 2 }) });
const session = (user: CurrentUser | null): UserContextValue => ({ user, loading: false, error: null,
  signedOut: user === null, refetch: vi.fn(), logout: vi.fn() });

beforeEach(() => {
  vi.spyOn(collectionsApi, 'getAll').mockResolvedValue([createMockCollection()]);
  vi.spyOn(categoriesApi, 'getAll').mockResolvedValue([createMockCategory()]);
  vi.spyOn(itemsApi, 'getById').mockResolvedValue(createMockItem());
  vi.spyOn(itemsApi, 'getAll').mockResolvedValue({ items: [createMockItem()], etag: 'v1', notModified: false });
  vi.spyOn(templatesApi, 'getAll').mockResolvedValue([createMockItemTemplate()]);
  vi.spyOn(suggestionsApi, 'get').mockResolvedValue({ categories: ['Book'], names: ['Author'] });
  vi.spyOn(suggestionsApi, 'sync').mockResolvedValue({ categories: [], names: [] });
  vi.spyOn(themesApi, 'getAll').mockResolvedValue([createMockCollectionTheme({ name: 'General' })]);
});
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

function setup(initialUser: CurrentUser | null = first) {
  let data!: DataContextValue;
  const navigate = vi.fn();
  function Consumer() {
    const value = useData();
    const [draft, setDraft] = useState('');
    useEffect(() => { data = value; }, [value]);
    return <input aria-label="Draft" value={draft} onChange={event => setDraft(event.target.value)} />;
  }
  const view = (user: CurrentUser | null, extra: Partial<UserContextValue> = {}) => <StrictMode>
    <UserContext.Provider value={{ ...session(user), ...extra }}>
      <WorkspaceSession navigate={navigate}><Consumer /></WorkspaceSession>
    </UserContext.Provider>
  </StrictMode>;
  const rendered = render(view(initialUser));
  return { ...rendered, navigate, getData: () => data,
    change: (user: CurrentUser | null, extra?: Partial<UserContextValue>) => rendered.rerender(view(user, extra)) };
}

async function populate(getData: () => DataContextValue) {
  await act(async () => {
    await Promise.all([getData().loadCollections(), getData().loadCategoriesForCollection(1), getData().loadItemsForCategory(1), getData().loadItemById(1),
      getData().loadPropertySuggestions(1), getData().loadThemes()]);
  });
  act(() => getData().setCurrentCollection(createMockCollection()));
}

it.each(['workspace', 'user'] as const)('retires every domain cache and route draft when the %s changes', async identity => {
  const { getData, change, navigate } = setup();
  await populate(getData);
  fireEvent.change(screen.getByLabelText('Draft'), { target: { value: 'Old workspace draft' } });
  expect(getData().collections).toHaveLength(1);
  expect(getData().categories).toHaveLength(1);
  expect(getData().items).toHaveLength(1);
  expect(getData().itemDetails.size).toBe(1);
  expect(getData().propertyNameSuggestions).toEqual(['Author']);
  expect(getData().themes).toHaveLength(1);
  change(identity === 'workspace' ? second : createMockCurrentUser({ userId: 2 }));
  expect(getData().currentCollection).toBeNull();
  expect(getData().collections).toEqual([]);
  expect(getData().categories).toEqual([]);
  expect(getData().items).toEqual([]);
  expect(getData().itemDetails.size).toBe(0);
  expect(getData().propertyNameSuggestions).toEqual([]);
  expect(getData().themes).toEqual([]);
  expect(screen.getByLabelText('Draft')).toHaveValue('');
  expect(navigate).toHaveBeenCalledExactlyOnceWith('/collections');
  change(first);
  expect(getData().collections).toEqual([]);
  expect(navigate).toHaveBeenCalledTimes(2);
});

it('preserves caches and drafts across refreshes of the same identity, including loading and metadata changes', async () => {
  const { getData, change, navigate } = setup();
  await populate(getData);
  const records = getData().itemDetails;
  const collections = getData().collections;
  fireEvent.change(screen.getByLabelText('Draft'), { target: { value: 'Unsaved work' } });
  change({ ...first, email: 'updated@example.test', activeWorkspace: { ...first.activeWorkspace!, slug: 'reading-room' } }, { loading: true });
  expect(getData().collections).toBe(collections);
  expect(getData().itemDetails).toBe(records);
  expect(screen.getByLabelText('Draft')).toHaveValue('Unsaved work');
  expect(navigate).not.toHaveBeenCalled();
  expect(collectionsApi.getAll).toHaveBeenCalledOnce();
});

it('clears sign-out state and preserves requested routes on an initial sign-in', async () => {
  const { getData, change, navigate } = setup(null);
  change(first);
  await populate(getData);
  change(null);
  expect(getData().collections).toEqual([]);
  expect(getData().itemDetails.size).toBe(0);
  change(second);
  expect(getData().collections).toEqual([]);
  expect(navigate).not.toHaveBeenCalled();
});

it('supports the legacy workspace ID while the session lacks active-workspace metadata', async () => {
  const legacy = { ...first, activeWorkspace: undefined } as unknown as CurrentUser;
  const { change, getData, navigate } = setup(legacy);
  await populate(getData);
  change({ ...legacy, workspaceId: 2 });
  expect(getData().collections).toEqual([]);
  expect(navigate).toHaveBeenCalledExactlyOnceWith('/collections');
});

it('ignores old workspace reads completing after the new workspace has loaded', async () => {
  const { getData, change } = setup();
  const pendingCollections = deferred<ReturnType<typeof createMockCollection>[]>();
  const pendingItem = deferred<ReturnType<typeof createMockItem>>();
  vi.mocked(collectionsApi.getAll).mockReturnValueOnce(pendingCollections.promise);
  vi.mocked(itemsApi.getById).mockReturnValueOnce(pendingItem.promise);
  let oldReads!: Promise<unknown>;
  act(() => { oldReads = Promise.all([getData().loadCollections(), getData().loadItemById(1)]); });
  change(second);
  const current = createMockCollection({ collectionId: 2, workspaceId: 2, name: 'Current workspace' });
  vi.mocked(collectionsApi.getAll).mockResolvedValueOnce([current]);
  await act(async () => { await getData().loadCollections(); });
  await act(async () => {
    pendingCollections.resolve([createMockCollection()]);
    pendingItem.resolve(createMockItem());
    await oldReads;
  });
  expect(getData().collections).toEqual([current]);
  expect(getData().itemDetails.size).toBe(0);
});

it('cancels queued suggestion synchronization when a workspace session ends', async () => {
  vi.useFakeTimers();
  const { getData, change } = setup();
  await act(async () => { await getData().syncPropertySuggestions(1); });
  change(second);
  await act(async () => { await vi.advanceTimersByTimeAsync(2100); });
  expect(suggestionsApi.sync).not.toHaveBeenCalled();
});

it('keeps collection subscribers unchanged when only item state changes', async () => {
  const collectionRenders = vi.fn();
  const itemRenders = vi.fn();
  let items!: ReturnType<typeof hooks.useItemsData>;
  function Collections() {
    const data = hooks.useCollectionsData();
    useEffect(() => { collectionRenders(data); });
    return <p>{data.collections.length} collections</p>;
  }
  function Items() {
    const data = hooks.useItemsData();
    useEffect(() => { items = data; itemRenders(data); });
    return <p>{data.itemDetails.size} items</p>;
  }
  render(<DataProvider><Collections /><Items /></DataProvider>);
  expect(collectionRenders).toHaveBeenCalledOnce();
  await act(async () => { await items.loadItemById(1); });
  expect(screen.getByText('1 items')).toBeInTheDocument();
  expect(collectionRenders).toHaveBeenCalledOnce();
  expect(itemRenders).toHaveBeenCalledTimes(2);
});

it.each(Object.entries(hooks))('%s rejects a missing provider', (_name, hook) => {
  expect(() => renderHook(hook as () => unknown)).toThrow('Data hooks must be used within a DataProvider');
});

it.each([['user', useUser], ['toast', useToast]] as const)('requires the %s provider at its composition boundary', (_name, hook) => {
  expect(() => renderHook(hook as () => unknown)).toThrow(/must be used within a .*Provider/);
});

it('finishes workspace creation through the session boundary even when the old wizard is retired', async () => {
  const created = { workspaceId: 2, workspaceName: 'Reading room', workspaceRole: WorkspaceRole.WorkspaceAdmin,
    collectionId: 20, collectionName: 'Books' };
  vi.spyOn(workspacesApi, 'setup').mockResolvedValue(created);
  const complete = vi.fn();
  const refreshed = vi.fn();
  function SignedIn({ children }: { children: ReactNode }) {
    const [user, setUser] = useState(first);
    const refetch = async () => { refreshed(); setUser(second); };
    return <UserContext.Provider value={{ ...session(user), refetch }}>{children}</UserContext.Provider>;
  }
  function Application() {
    const navigate = useNavigate();
    return <WorkspaceSession navigate={navigate}><Routes>
      <Route path="/create" element={<WorkspaceSetupWizard onComplete={complete} />} />
      <Route path="/collections" element={<h1>New workspace collections</h1>} />
    </Routes></WorkspaceSession>;
  }
  render(<MemoryRouter initialEntries={['/create']}><SignedIn><Application /></SignedIn></MemoryRouter>);
  await userEvent.type(await screen.findByLabelText(/New Workspace Name/), 'Reading room');
  await userEvent.click(screen.getByRole('button', { name: 'Next' }));
  await screen.findByRole('button', { name: /General/ });
  await userEvent.click(screen.getByRole('button', { name: 'Next' }));
  await userEvent.click(screen.getByRole('button', { name: 'Create Workspace' }));
  await waitFor(() => expect(screen.getByRole('heading', { name: 'New workspace collections' })).toBeInTheDocument());
  expect(workspacesApi.setup).toHaveBeenCalledOnce();
  expect(refreshed).toHaveBeenCalledOnce();
});
