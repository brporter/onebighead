import { useState } from 'react';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, Link, RouterProvider } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import UserContext from '../../src/contexts/UserContext';
import { TemplatesContext } from '../../src/contexts/dataContexts';
import { SessionChangesProvider } from '../../src/contexts/SessionChangesProvider';
import { useUnsavedNavigation } from '../../src/data/shared/useUnsavedNavigation';
import ItemTemplateEditor from '../../src/components/template/ItemTemplateEditor';
import UserButton from '../../src/components/user/UserButton';
import WorkspaceSwitcher from '../../src/components/common/WorkspaceSwitcher';
import { bulkUpdatesApi, workspacesApi } from '../../src/api';
import { createMockCurrentUser, createMockDataContextValue, createMockItemTemplate, createMockWorkspaceMembership } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';
import type { ItemTemplate } from '../../src/utils/types';

const template = createMockItemTemplate({ name: 'Books', properties: [{ category: 'Details', name: 'Author' }] });
const current = createMockWorkspaceMembership({ workspaceId: 1, workspaceName: 'First workspace' });
const other = createMockWorkspaceMembership({ workspaceId: 2, workspaceName: 'Other workspace' });
const user = createMockCurrentUser({ activeWorkspace: current, workspaces: [current, other] });
const logout = vi.fn();
let data = createMockDataContextValue();
beforeEach(() => {
  data = createMockDataContextValue({
    fetchItemTemplates: vi.fn().mockResolvedValue([template]),
    createItemTemplate: vi.fn().mockResolvedValue(template),
    updateItemTemplate: vi.fn().mockResolvedValue(template),
    deleteItemTemplate: vi.fn().mockResolvedValue(undefined),
  });
  logout.mockReset().mockResolvedValue(undefined);
  vi.spyOn(window, 'confirm').mockReturnValue(false);
  vi.spyOn(workspacesApi, 'switch').mockResolvedValue({ success: true, workspaceId: 2, workspaceName: 'Other workspace' });
  vi.spyOn(bulkUpdatesApi, 'preview').mockResolvedValue({ affectedItemCount: 0 });
});
afterEach(() => vi.restoreAllMocks());

function TemplatePage() {
  const [status, report] = useState({ dirty: false, pending: false });
  useUnsavedNavigation(status.dirty, status.pending);
  return <><Link to="/library">Library</Link><WorkspaceSwitcher /><UserButton />
    <ItemTemplateEditor onClose={() => {}} onStatusChange={report} /></>;
}
function setup() {
  const router = createMemoryRouter([
    { path: '/templates', element: <TemplatePage /> },
    { path: '/library', element: <h1>Library</h1> },
  ], { initialEntries: ['/library', '/templates'], initialIndex: 1 });
  const view = render(<UserContext value={{ user, loading: false, error: null, signedOut: false, refetch: vi.fn(), logout }}>
    <TemplatesContext value={data}><SessionChangesProvider><RouterProvider router={router} /></SessionChangesProvider></TemplatesContext>
  </UserContext>);
  return { ...view, router };
}
async function edit() {
  await userEvent.click(within(await screen.findByRole('article', { name: 'Books' })).getByRole('button', { name: 'Edit' }));
}
async function selectOtherWorkspace() {
  await userEvent.click(screen.getByRole('button', { name: /Other workspace/, hidden: true }));
}

it('retains drafts on rejected sign-out and prevents session changes and history navigation during a template save', async () => {
  const pending = deferred<ItemTemplate>();
  vi.mocked(data.updateItemTemplate).mockReturnValue(pending.promise);
  const { router } = setup();
  await edit();
  fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Keep these notes' } });
  await userEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
  expect(logout).not.toHaveBeenCalled();
  expect(window.confirm).toHaveBeenCalledOnce();
  vi.mocked(window.confirm).mockClear();
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
  await userEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
  expect(screen.getByRole('alert')).toHaveTextContent('Wait for the current action');
  await selectOtherWorkspace();
  expect(workspacesApi.switch).not.toHaveBeenCalled();
  expect(logout).not.toHaveBeenCalled();
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/templates');
  expect(window.confirm).not.toHaveBeenCalled();
  await act(async () => pending.reject(new Error('Save unavailable')));
  expect(screen.getByLabelText('Description')).toHaveValue('Keep these notes');
  expect(screen.getByLabelText('Description')).toBeEnabled();
  await userEvent.click(screen.getByRole('link', { name: 'Library' }));
  expect(window.confirm).toHaveBeenCalledOnce();
  expect(router.state.location.pathname).toBe('/templates');
});

it('releases the saved draft before the next navigation without another discard prompt', async () => {
  const { router } = setup();
  await edit();
  fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Saved notes' } });
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
  await screen.findByRole('heading', { name: 'Item Templates' });
  await userEvent.click(screen.getByRole('link', { name: 'Library' }));
  expect(router.state.location.pathname).toBe('/library');
  expect(window.confirm).not.toHaveBeenCalled();
  expect(data.updateItemTemplate).toHaveBeenCalledOnce();
});

it('keeps a new-template request protected until it completes', async () => {
  const pending = deferred<ItemTemplate>();
  vi.mocked(data.createItemTemplate).mockReturnValue(pending.promise);
  const { router } = setup();
  await userEvent.click(screen.getByRole('button', { name: '+ New Template' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Template Name' }), { target: { value: 'Cameras' } });
  await userEvent.click(screen.getByRole('button', { name: 'Create Template' }));
  await selectOtherWorkspace();
  expect(workspacesApi.switch).not.toHaveBeenCalled();
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/templates');
  await act(async () => pending.resolve(template));
  await screen.findByRole('heading', { name: 'Item Templates' });
  await userEvent.click(screen.getByRole('link', { name: 'Library' }));
  expect(router.state.location.pathname).toBe('/library');
  expect(window.confirm).not.toHaveBeenCalled();
});

it('does not switch sessions during template deletion and releases the guard after failure', async () => {
  const pending = deferred<void>();
  vi.mocked(data.deleteItemTemplate).mockReturnValue(pending.promise);
  const { router } = setup();
  vi.mocked(window.confirm).mockReturnValue(true);
  await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));
  vi.mocked(window.confirm).mockClear();
  await selectOtherWorkspace();
  expect(workspacesApi.switch).not.toHaveBeenCalled();
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/templates');
  await act(async () => pending.reject(new Error('Delete unavailable')));
  await userEvent.click(screen.getByRole('link', { name: 'Library' }));
  expect(router.state.location.pathname).toBe('/library');
  expect(window.confirm).not.toHaveBeenCalled();
});

it('protects bulk submission after the definition was saved and releases navigation after completion', async () => {
  const completed = { jobId: 'template-job', status: 'Completed', totalItems: 1, processedItems: 1, failedItems: 0 };
  const pending = deferred<typeof completed>();
  vi.mocked(bulkUpdatesApi.preview).mockResolvedValue({ affectedItemCount: 1 });
  vi.spyOn(bulkUpdatesApi, 'enqueue').mockReturnValue(pending.promise);
  const { router } = setup();
  await edit();
  fireEvent.change(screen.getByRole('textbox', { name: 'Property name' }), { target: { value: 'Writer' } });
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
  const dialog = await screen.findByRole('dialog', { name: 'Bulk property update' });
  await userEvent.click(within(dialog).getByRole('button', { name: 'Apply to All' }));
  expect(screen.getByRole('button', { name: 'Back to templates' })).toBeDisabled();
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/templates');
  expect(window.confirm).not.toHaveBeenCalled();
  await act(async () => pending.resolve(completed));
  await userEvent.click(within(dialog).getByRole('button', { name: 'Close' }));
  await screen.findByRole('heading', { name: 'Item Templates' });
  await userEvent.click(screen.getByRole('link', { name: 'Library' }));
  expect(router.state.location.pathname).toBe('/library');
  expect(data.updateItemTemplate).toHaveBeenCalledOnce();
  expect(bulkUpdatesApi.enqueue).toHaveBeenCalledOnce();
});

it('can leave a cancellable preview after a successful save without accepting stale results', async () => {
  const pending = deferred<{ affectedItemCount: number }>();
  vi.mocked(bulkUpdatesApi.preview).mockReturnValue(pending.promise);
  const { router } = setup();
  await edit();
  fireEvent.change(screen.getByRole('textbox', { name: 'Property name' }), { target: { value: 'Writer' } });
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
  await screen.findByText('Checking related items…');
  const signal = vi.mocked(bulkUpdatesApi.preview).mock.calls[0][1]!.signal!;
  await act(async () => { await router.navigate(-1); });
  expect(router.state.location.pathname).toBe('/library');
  expect(signal.aborted).toBe(true);
  expect(window.confirm).not.toHaveBeenCalled();
  await act(async () => pending.resolve({ affectedItemCount: 1 }));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});
