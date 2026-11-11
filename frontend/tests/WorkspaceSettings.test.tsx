import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { WorkspaceSettings } from '../src/components/workspace/WorkspaceSettings';
import { workspacesApi } from '../src/api';
import { WorkspaceRole, type WorkspaceMembership } from '../src/utils/types';
import { deferred } from './testUtils/deferred';
import { useUser } from '../src/contexts/useUser';
import { createMockCurrentUser } from './testUtils';

vi.mock('../src/api', () => ({ workspacesApi: { getRestorableWorkspaces: vi.fn(), switch: vi.fn(), leave: vi.fn(), restoreWorkspace: vi.fn() } }));
vi.mock('../src/contexts/useUser', () => ({ useUser: vi.fn() }));
vi.mock('../src/components/wizard/WorkspaceSetupWizard', () => ({ default: ({ onComplete, onCancel }: { onComplete: () => void; onCancel: () => void }) => <div><button onClick={onComplete}>Complete setup</button><button onClick={onCancel}>Cancel setup</button></div> }));
vi.mock('../src/components/workspace/WorkspaceEditModal', () => ({ default: ({ onClose, refresh }: { onClose: () => void; refresh: () => Promise<void> }) => <div role="dialog" aria-label="Edit workspace"><button onClick={onClose}>Cancel edit</button><button onClick={() => { void refresh(); }}>Save workspace</button></div> }));
vi.mock('../src/components/workspace/WorkspaceDeletionSection', () => ({ WorkspaceDeletionSection: ({ exportAvailable, onClose, refresh }: { exportAvailable: boolean; onClose: () => void; refresh: () => Promise<void> }) => <div role="dialog" aria-label="Delete workspace" data-export={String(exportAvailable)}><button onClick={() => { void refresh(); onClose(); }}>Confirm deletion</button><button onClick={onClose}>Cancel deletion</button></div> }));

const home: WorkspaceMembership = { workspaceId: 1, workspaceName: 'Home', workspaceRole: WorkspaceRole.WorkspaceAdmin, hasCompletedWelcome: true };
const shared: WorkspaceMembership = { workspaceId: 2, workspaceName: 'Shared', workspaceRole: WorkspaceRole.Normal, hasCompletedWelcome: false };
const onCreated = vi.fn();
const refetch = vi.fn();
const props = { memberships: [home, shared], activeWorkspaceId: 1, onCreated };

beforeEach(() => {
  vi.resetAllMocks();
  refetch.mockResolvedValue(undefined);
  vi.mocked(useUser).mockReturnValue({ user: createMockCurrentUser(), loading: false, error: null, signedOut: false, refetch, logout: vi.fn() });
  vi.mocked(workspacesApi.getRestorableWorkspaces).mockResolvedValue([]);
  vi.mocked(workspacesApi.switch).mockResolvedValue({ success: true, workspaceId: 2, workspaceName: 'Shared' });
  vi.mocked(workspacesApi.leave).mockResolvedValue({ success: true });
  vi.mocked(workspacesApi.restoreWorkspace).mockResolvedValue({ workspaceId: 3, name: 'Archive' });
  vi.spyOn(window, 'confirm').mockReturnValue(true);
});

it('identifies current workspaces and serializes switch, leave and restore actions', async () => {
  const pending = deferred<{ success: boolean; workspaceId: number; workspaceName: string }>();
  vi.mocked(workspacesApi.switch).mockReturnValueOnce(pending.promise);
  vi.mocked(workspacesApi.getRestorableWorkspaces).mockResolvedValue([{ workspaceId: 3, name: 'Archive', deletedAt: '2026-11-01', daysRemaining: 21, stats: { collectionCount: 2, itemCount: 4, categoryCount: 1, imageCount: 0 } }]);
  render(<WorkspaceSettings {...props} />);
  expect(within(screen.getByRole('article', { name: 'Home' })).getByText('Current')).toBeInTheDocument();
  expect(screen.getByText('Setup not completed')).toBeInTheDocument();
  expect(await screen.findByText('21 days until permanent deletion')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Switch to Shared' }));
  expect(screen.getByRole('button', { name: 'Leave Shared' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Restore Archive' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Delete Home' })).toBeDisabled();
  expect(screen.getByText('Updating workspace…')).toHaveAttribute('role', 'status');
  await act(async () => pending.resolve({ success: true, workspaceId: 2, workspaceName: 'Shared' }));
  expect(refetch).toHaveBeenCalledExactlyOnceWith({ throwOnError: true, endSessionIfAnonymous: true });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  fireEvent.click(screen.getByRole('button', { name: 'Leave Shared' }));
  expect(workspacesApi.leave).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Leave Shared' }));
  await waitFor(() => expect(refetch).toHaveBeenCalledTimes(2));
  vi.mocked(workspacesApi.restoreWorkspace).mockRejectedValueOnce(new Error('Restore unavailable'));
  // Session refresh starts a separate recovery-list read; wait for its UI too.
  await waitFor(() => expect(screen.getByRole('button', { name: 'Restore Archive' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Restore Archive' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Restore unavailable');
  await waitFor(() => expect(screen.getByRole('button', { name: 'Restore Archive' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Restore Archive' }));
  await waitFor(() => expect(refetch).toHaveBeenCalledTimes(4));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Restore Archive' })).toBeEnabled());
});

it('reports failed recovery reads, retries them, and explains empty membership lists', async () => {
  vi.mocked(workspacesApi.getRestorableWorkspaces).mockRejectedValueOnce(new Error('Offline'));
  render(<WorkspaceSettings {...props} memberships={[]} activeWorkspaceId={undefined} />);
  expect(screen.getByText('No active workspaces')).toBeInTheDocument();
  expect(screen.getByText('Loading recoverable workspaces…')).toBeInTheDocument();
  expect(await screen.findByRole('alert')).toHaveTextContent('Offline');
  fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
  expect(await screen.findByText('No workspaces to restore')).toBeInTheDocument();
});

it('keeps create and edit sessions local and limits backup export to the active workspace', async () => {
  render(<WorkspaceSettings {...props} memberships={[home, { ...home, workspaceId: 4, workspaceName: 'Other' }]} />);
  await screen.findByText('No workspaces to restore');
  fireEvent.click(screen.getByRole('button', { name: 'Delete Home' }));
  expect(screen.getByRole('dialog')).toHaveAttribute('data-export', 'true');
  fireEvent.click(screen.getByRole('button', { name: 'Cancel deletion' }));
  fireEvent.click(screen.getByRole('button', { name: 'Edit Home' }));
  fireEvent.click(screen.getByRole('button', { name: 'Cancel edit' }));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Edit Other' }));
  fireEvent.click(screen.getByRole('button', { name: 'Save workspace' }));
  expect(refetch).toHaveBeenCalledExactlyOnceWith({ throwOnError: true, endSessionIfAnonymous: true });
  fireEvent.click(screen.getByRole('button', { name: 'Cancel edit' }));
  fireEvent.click(screen.getByRole('button', { name: 'Delete Other' }));
  expect(screen.getByRole('dialog')).toHaveAttribute('data-export', 'false');
  fireEvent.click(screen.getByRole('button', { name: 'Confirm deletion' }));
  expect(refetch).toHaveBeenCalledTimes(2);
  await waitFor(() => expect(workspacesApi.getRestorableWorkspaces).toHaveBeenCalledTimes(2));
  fireEvent.click(screen.getByRole('button', { name: '+ Create New Workspace' }));
  fireEvent.click(screen.getByRole('button', { name: 'Cancel setup' }));
  expect(screen.queryByRole('button', { name: 'Complete setup' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: '+ Create New Workspace' }));
  fireEvent.click(screen.getByRole('button', { name: 'Complete setup' }));
  expect(onCreated).toHaveBeenCalledOnce();
});

it('does not offer leaving the only workspace', async () => {
  render(<WorkspaceSettings {...props} memberships={[shared]} activeWorkspaceId={2} />);
  await screen.findByText('No workspaces to restore');
  expect(screen.queryByRole('button', { name: /Leave/ })).not.toBeInTheDocument();
});

it('retires the workspace editor when a refresh removes administrative access', async () => {
  const { rerender } = render(<WorkspaceSettings {...props} />);
  await screen.findByText('No workspaces to restore');
  fireEvent.click(screen.getByRole('button', { name: 'Edit Home' }));
  expect(screen.getByRole('dialog')).toBeInTheDocument();
  rerender(<WorkspaceSettings {...props} memberships={[{ ...home, workspaceRole: WorkspaceRole.Normal }, shared]} />);
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Edit Home' })).not.toBeInTheDocument();
});

it('keeps standalone controls locked through read-only recovery and reports navigation status', async () => {
  const onStatusChange = vi.fn();
  refetch.mockRejectedValueOnce(new Error('Session offline')).mockResolvedValue(undefined);
  vi.mocked(workspacesApi.switch).mockRejectedValueOnce(new Error('Response lost'));
  render(<WorkspaceSettings {...props} onStatusChange={onStatusChange} />);
  await screen.findByText('No workspaces to restore');
  fireEvent.click(screen.getByRole('button', { name: 'Switch to Shared' }));
  const recovery = await screen.findByRole('dialog', { name: 'Updating your session' });
  const retry = await within(recovery).findByRole('button', { name: 'Retry session refresh' });
  expect(within(recovery).getByRole('alert')).toHaveTextContent('Session offline');
  expect(onStatusChange).toHaveBeenLastCalledWith({ dirty: false, pending: true });
  expect(screen.getByRole('button', { name: '+ Create New Workspace' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Switch to Shared' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Leave Shared' })).toBeDisabled();
  fireEvent.click(retry);
  await waitFor(() => expect(onStatusChange).toHaveBeenLastCalledWith({ dirty: false, pending: false }));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(screen.getByRole('alert')).toHaveTextContent('Review your workspaces before trying again.');
  expect(refetch).toHaveBeenCalledTimes(2);
  expect(workspacesApi.switch).toHaveBeenCalledExactlyOnceWith(2);
});
