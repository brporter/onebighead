import { describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DeletionConfirmationModal } from '../src/components/common/DeletionConfirmationModal';
import { SupportModal } from '../src/components/support/SupportModal';
import { WorkspaceRestorationModal } from '../src/components/workspace/WorkspaceRestorationModal';
import { createSupportRequest } from '../src/api';

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
    render(<WorkspaceRestorationModal isOpen onCreateNew={onCreateNew} onRestoreComplete={vi.fn()} />);
    await screen.findByRole('button', { name: 'Continue' });
    const dialog = screen.getByRole('dialog');
    fireEvent(dialog, new Event('cancel', { cancelable: true }));
    expect(dialog).toHaveAttribute('open');
    await userEvent.click(screen.getByRole('radio', { name: 'Create a new workspace' }));
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
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
