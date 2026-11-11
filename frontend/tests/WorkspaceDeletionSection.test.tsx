import { useState } from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { WorkspaceDeletionSection } from '../src/components/workspace/WorkspaceDeletionSection';
import { workspacesApi, exportApi, authApi } from '../src/api';
import { WorkspaceRole } from '../src/utils/types';
import type { WorkspaceStats, WorkspaceDeletionResponse } from '../src/api/workspaces';
import { saveDownload } from '../src/utils/saveDownload';
import { deferred } from './testUtils/deferred';

vi.mock('../src/api', () => ({ workspacesApi: { getStats: vi.fn(), deleteWorkspace: vi.fn() }, exportApi: { downloadExport: vi.fn() }, authApi: { logout: vi.fn() } }));
vi.mock('../src/utils/saveDownload', () => ({ saveDownload: vi.fn() }));
const workspace = { workspaceId: 4, workspaceName: 'Library', workspaceRole: WorkspaceRole.WorkspaceAdmin, hasCompletedWelcome: true };
const stats: WorkspaceStats = { workspaceId: 4, workspaceName: 'Library', collectionCount: 2, itemCount: 8, categoryCount: 3, imageCount: 5, userCount: 1, adminCount: 1 };
const onClose = vi.fn();
const refresh = vi.fn();
const onStatusChange = vi.fn();
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubGlobal('location', { href: '' });
  vi.mocked(workspacesApi.getStats).mockResolvedValue(stats);
  vi.mocked(workspacesApi.deleteWorkspace).mockResolvedValue({ success: true });
  refresh.mockResolvedValue(undefined);
});

function show(exportAvailable = true) {
  function Host() {
    const [open, setOpen] = useState(true);
    return open ? <WorkspaceDeletionSection workspace={workspace} exportAvailable={exportAvailable} refresh={refresh} onStatusChange={onStatusChange}
      onClose={() => { onClose(); setOpen(false); }} /> : <button onClick={() => setOpen(true)}>Open deletion</button>;
  }
  return render(<Host />);
}
async function ready() {
  await screen.findByText('This workspace will be deleted.');
  return screen.findByRole('dialog', { name: 'Delete "Library"' });
}

it('prepares statistics, reports failures, retries and aborts late reads on unmount', async () => {
  const pending = deferred<WorkspaceStats>();
  vi.mocked(workspacesApi.getStats).mockRejectedValueOnce(new Error('Stats unavailable')).mockReturnValueOnce(pending.promise);
  const { unmount } = show();
  expect(onStatusChange).toHaveBeenLastCalledWith({ dirty: false, pending: true });
  expect(await screen.findByRole('alert')).toHaveTextContent('Stats unavailable');
  expect(onStatusChange).toHaveBeenLastCalledWith({ dirty: false, pending: false });
  fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
  expect(screen.getByText('Loading deletion information…')).toBeInTheDocument();
  expect(onStatusChange).toHaveBeenLastCalledWith({ dirty: false, pending: true });
  const signal = vi.mocked(workspacesApi.getStats).mock.calls[1][1]!.signal!;
  unmount();
  expect(signal.aborted).toBe(true);
  expect(onStatusChange).toHaveBeenLastCalledWith({ dirty: false, pending: false });
  await act(async () => pending.resolve(stats));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});

it('allows cancelling a pending statistics request', async () => {
  const pending = deferred<WorkspaceStats>();
  vi.mocked(workspacesApi.getStats).mockReturnValue(pending.promise);
  show();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(onClose).toHaveBeenCalledOnce();
  expect(vi.mocked(workspacesApi.getStats).mock.calls[0][1]!.signal!.aborted).toBe(true);
  await act(async () => pending.resolve(stats));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});

it('protects export, preserves failed deletion and requires a fresh review when requested', async () => {
  const backup = deferred<{ blob: Blob; filename: string }>();
  const deletion = deferred<WorkspaceDeletionResponse>();
  vi.mocked(exportApi.downloadExport).mockReturnValue(backup.promise);
  vi.mocked(workspacesApi.deleteWorkspace).mockReturnValueOnce(deletion.promise).mockResolvedValueOnce({ success: false }).mockResolvedValue({ success: true });
  show();
  const dialog = await ready();
  expect(screen.getByText('8')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Download Export' }));
  expect(onStatusChange).toHaveBeenLastCalledWith({ dirty: false, pending: true });
  expect(screen.getByRole('button', { name: 'Delete Workspace' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
  fireEvent(dialog, new Event('cancel', { cancelable: true }));
  expect(dialog).toHaveAttribute('open');
  const file = { blob: new Blob(['archive']), filename: 'library.zip' };
  await act(async () => backup.resolve(file));
  expect(saveDownload).toHaveBeenCalledWith(file);
  expect(onStatusChange).toHaveBeenLastCalledWith({ dirty: false, pending: false });
  fireEvent.click(screen.getByRole('button', { name: 'Delete Workspace' }));
  expect(screen.getByRole('button', { name: 'Deleting...' })).toBeDisabled();
  await act(async () => deletion.reject(new Error('Delete unavailable')));
  expect(await screen.findByText('Delete unavailable')).toBeInTheDocument();
  expect(refresh).toHaveBeenCalledOnce();
  expect(onClose).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Review deletion information' }));
  await ready();
  expect(screen.getByRole('checkbox')).not.toBeChecked();
  expect(workspacesApi.getStats).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Delete Workspace' }));
  expect(await screen.findByText('Failed to delete workspace')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Delete Workspace' }));
  await waitFor(() => expect(onClose).toHaveBeenCalledOnce());
  expect(refresh).toHaveBeenCalledTimes(3);
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Open deletion' }));
  await ready();
  expect(screen.getByRole('checkbox')).not.toBeChecked();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(onClose).toHaveBeenCalledTimes(2);
});

it('does not export another workspace and completes deletion without a redundant logout', async () => {
  vi.mocked(workspacesApi.deleteWorkspace).mockResolvedValue({ success: true, userSoftDeleted: true });
  show(false);
  await ready();
  expect(screen.queryByRole('button', { name: 'Download Export' })).not.toBeInTheDocument();
  expect(screen.getByText(/cancel and switch to it first/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Delete Workspace' }));
  await waitFor(() => expect(window.location.href).toBe('/'));
  expect(workspacesApi.deleteWorkspace).toHaveBeenCalledExactlyOnceWith(4);
  expect(refresh).toHaveBeenCalledOnce();
  expect(authApi.logout).not.toHaveBeenCalled();
});

it('keeps standalone session recovery protected and never repeats the deletion', async () => {
  refresh.mockRejectedValueOnce(new Error('Session offline')).mockResolvedValue(undefined);
  vi.mocked(workspacesApi.deleteWorkspace).mockRejectedValue(new Error('Response lost'));
  show();
  await ready();
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Delete Workspace' }));
  const recovery = await screen.findByRole('dialog', { name: 'Updating your session' });
  await within(recovery).findByRole('button', { name: 'Retry session refresh' });
  expect(onStatusChange).toHaveBeenLastCalledWith({ dirty: false, pending: true });
  expect(within(recovery).getByRole('alert')).toHaveTextContent('Session offline');
  fireEvent.click(within(recovery).getByRole('button', { name: 'Retry session refresh' }));
  await waitFor(() => expect(onStatusChange).toHaveBeenLastCalledWith({ dirty: false, pending: false }));
  expect(screen.getByRole('alert')).toHaveTextContent('Review deletion information before trying again.');
  expect(workspacesApi.deleteWorkspace).toHaveBeenCalledExactlyOnceWith(4);
  expect(refresh).toHaveBeenCalledTimes(2);
  expect(onClose).not.toHaveBeenCalled();
});

it.each([new Error('Backup unavailable'), null])('keeps export errors recoverable', async cause => {
  vi.mocked(exportApi.downloadExport).mockRejectedValue(cause);
  show();
  await ready();
  fireEvent.click(screen.getByRole('button', { name: 'Download Export' }));
  expect(await screen.findByText(cause instanceof Error ? 'Backup unavailable' : 'Export failed')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Download Export' })).toBeEnabled();
});
