import { describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DeletionConfirmationModal } from '../src/components/common/DeletionConfirmationModal';
import { SupportModal } from '../src/components/support/SupportModal';
import { WorkspaceRestorationModal } from '../src/components/workspace/WorkspaceRestorationModal';
import { createSupportRequest } from '../src/api';
import { DeletionBlockerReason } from '../src/api/account';

vi.mock('../src/api', () => ({ createSupportRequest: vi.fn(), workspacesApi: { getRestorableWorkspaces: vi.fn().mockResolvedValue([]), restoreWorkspaces: vi.fn() } }));

describe('native modal flows', () => {
  it('keeps deletion open during the request and preserves checkbox confirmation', async () => {
    const user = userEvent.setup();
    let finish!: () => void;
    const onConfirm = vi.fn(() => new Promise<void>(resolve => { finish = resolve; }));
    const onClose = vi.fn();
    render(<DeletionConfirmationModal isOpen onClose={onClose} onConfirm={onConfirm} title="Delete workspace" entityType="workspace" entityName="Test" confirmationType="checkbox" />);
    const button = screen.getByRole('button', { name: 'Delete Workspace' });
    expect(button).toBeDisabled();
    await user.click(screen.getByRole('checkbox'));
    await user.click(button);
    fireEvent.submit(screen.getByRole('form', { name: 'Confirm deletion' }));
    expect(onConfirm).toHaveBeenCalledOnce();
    fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }));
    expect(onClose).not.toHaveBeenCalled();
    await act(async () => finish());
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('allows Escape to close a deletion dialog before submission', () => {
    const onClose = vi.fn();
    render(<DeletionConfirmationModal isOpen onClose={onClose} onConfirm={vi.fn()} title="Delete account" entityType="account" entityName="Test" confirmationType="text-match" />);
    fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('validates form submission and blocks submission while a backup is pending', () => {
    const onConfirm = vi.fn();
    const props = { isOpen: true, onClose: vi.fn(), onConfirm, title: 'Delete workspace', entityType: 'workspace' as const, entityName: 'Library', confirmationType: 'checkbox' as const };
    const { rerender } = render(<DeletionConfirmationModal {...props} />);
    fireEvent.submit(screen.getByRole('form', { name: 'Confirm deletion' }));
    expect(onConfirm).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('checkbox'));
    rerender(<DeletionConfirmationModal {...props} isExporting />);
    fireEvent.submit(screen.getByRole('form', { name: 'Confirm deletion' }));
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('handles an unspecified deletion failure and hides a closed dialog', async () => {
    const props = { isOpen: true, onClose: vi.fn(), onConfirm: vi.fn().mockRejectedValue(null), title: 'Delete account', entityType: 'account' as const, entityName: 'Account', confirmationType: 'checkbox' as const };
    const { rerender } = render(<DeletionConfirmationModal {...props} />);
    fireEvent.click(screen.getByLabelText('I understand that this action is permanent and cannot be undone.'));
    fireEvent.submit(screen.getByRole('form', { name: 'Confirm deletion' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Deletion failed');
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(props.onClose).toHaveBeenCalledOnce();
    rerender(<DeletionConfirmationModal {...props} isOpen={false} />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('does not resolve a transfer when its placeholder is selected', () => {
    const resolve = vi.fn();
    render(<DeletionConfirmationModal isOpen onClose={vi.fn()} onConfirm={vi.fn()} title="Delete account" entityType="account" entityName="Account" confirmationType="text-match" onResolveBlocker={resolve} blockers={[{
      workspaceId: 2, workspaceName: 'Library', reason: DeletionBlockerReason.SoleAdmin, transferToUserId: 3, users: [{ userId: 3, email: 'member@example.com' }],
    }]} />);
    fireEvent.change(screen.getByLabelText('Transfer admin to:'), { target: { value: '' } });
    expect(resolve).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Delete Account' })).toBeDisabled();
  });

  it('submits support requests and clears the form when dismissed', async () => {
    const user = userEvent.setup();
    vi.mocked(createSupportRequest).mockResolvedValue({} as Awaited<ReturnType<typeof createSupportRequest>>);
    const onClose = vi.fn();
    render(<SupportModal isOpen userEmail="user@example.com" onClose={onClose} />);
    await user.type(screen.getByPlaceholderText('Brief summary of your issue'), 'Help');
    await user.type(screen.getByPlaceholderText('Please describe your issue in detail...'), 'Details');
    await user.click(screen.getByRole('button', { name: 'Submit Request' }));
    expect(createSupportRequest).toHaveBeenCalledWith({ subject: 'Help', description: 'Details' });
    expect(screen.getByText('Request Submitted')).toBeInTheDocument();
    fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('requires a recovery choice before leaving the restoration dialog', async () => {
    const onCreateNew = vi.fn();
    render(<WorkspaceRestorationModal workspaces={[]} selectedIds={[]} toggle={vi.fn()} restore={vi.fn()} confirmed={false} pending={false} error={null} onReload={vi.fn()} onCreateNew={onCreateNew} />);
    expect(screen.getByRole('button', { name: 'Restore selected workspaces' })).toBeDisabled();
    const dialog = screen.getByRole('dialog');
    fireEvent(dialog, new Event('cancel', { cancelable: true }));
    expect(dialog).toHaveAttribute('open');
    await userEvent.click(screen.getByRole('button', { name: 'Create a new workspace' }));
    expect(onCreateNew).toHaveBeenCalledOnce();
  });
  it('uses native email validation before submitting an anonymous support request', async () => {
    const user = userEvent.setup();
    vi.mocked(createSupportRequest).mockClear();
    render(<SupportModal isOpen onClose={vi.fn()} />);
    await user.type(screen.getByLabelText(/Email/), 'user@localhost');
    await user.type(screen.getByLabelText(/Subject/), 'Help');
    await user.type(screen.getByLabelText(/Description/), 'Details');
    await user.click(screen.getByRole('button', { name: 'Submit Request' }));
    expect(screen.getByLabelText(/Email/)).toBeInvalid();
    expect(createSupportRequest).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText(/Email/), '.test');
    await user.click(screen.getByRole('button', { name: 'Submit Request' }));
    expect(createSupportRequest).toHaveBeenCalledWith({ subject: 'Help', description: 'Details', email: 'user@localhost.test' });
  });

});
