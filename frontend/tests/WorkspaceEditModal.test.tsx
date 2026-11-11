import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import WorkspaceEditModal from '../src/components/workspace/WorkspaceEditModal';
import { workspacesApi } from '../src/api';
import type { WorkspaceMembership } from '../src/utils/types';
import { WorkspaceRole } from '../src/utils/types';
import { deferred } from './testUtils/deferred';

vi.mock('../src/api', () => ({
  workspacesApi: {
    update: vi.fn(),
  },
}));

describe('WorkspaceEditModal', () => {
  const mockWorkspace: WorkspaceMembership = {
    workspaceId: 1,
    workspaceName: 'Test Workspace',
    workspaceRole: WorkspaceRole.WorkspaceAdmin,
    hasCompletedWelcome: true,
    slug: 'test-workspace',
  };

  const defaultProps = {
    workspace: mockWorkspace,
    isOpen: true,
    onClose: vi.fn(),
    refresh: vi.fn().mockResolvedValue(undefined),
    onSaved: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    HTMLDialogElement.prototype.showModal = vi.fn(function (this: HTMLDialogElement) {
      this.setAttribute('open', '');
    });
    HTMLDialogElement.prototype.close = vi.fn(function (this: HTMLDialogElement) {
      this.removeAttribute('open');
    });

    vi.mocked(workspacesApi.update).mockResolvedValue({
      workspaceId: 1,
      workspaceName: 'Test Workspace',
      slug: 'test-workspace',
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('rendering', () => {
    it('should render the modal with workspace name', () => {
      render(<WorkspaceEditModal {...defaultProps} />);

      expect(screen.getByText('Edit Workspace')).toBeInTheDocument();
      expect(screen.getByDisplayValue('Test Workspace')).toBeInTheDocument();
    });

    it('should render the Public Gallery section', () => {
      render(<WorkspaceEditModal {...defaultProps} />);

      expect(screen.getByText('Public Gallery')).toBeInTheDocument();
      expect(screen.getByLabelText('Gallery URL Slug')).toBeInTheDocument();
    });

    it('should show the slug reservation note', () => {
      render(<WorkspaceEditModal {...defaultProps} />);

      expect(screen.getByText('Reserve your gallery URL. Your gallery becomes active when you publish your first item.')).toBeInTheDocument();
    });

    it('should populate slug from workspace membership', () => {
      render(<WorkspaceEditModal {...defaultProps} />);

      expect(screen.getByDisplayValue('test-workspace')).toBeInTheDocument();
    });

    it('should auto-suggest slug from workspace name when no slug exists', () => {
      const workspaceNoSlug: WorkspaceMembership = {
        ...mockWorkspace,
        slug: null,
      };

      render(<WorkspaceEditModal {...defaultProps} workspace={workspaceNoSlug} />);

      expect(screen.getByDisplayValue('test-workspace')).toBeInTheDocument();
    });

    it('should show URL preview when slug is present', () => {
      render(<WorkspaceEditModal {...defaultProps} />);

      expect(screen.getByText('Gallery URL:')).toBeInTheDocument();
      expect(screen.getByText('/public/test-workspace')).toBeInTheDocument();
    });

    it('should preview the suggested slug even before it is valid', () => {
      const workspaceNoSlug: WorkspaceMembership = {
        ...mockWorkspace,
        slug: undefined,
        workspaceName: 'X',
      };

      render(<WorkspaceEditModal {...defaultProps} workspace={workspaceNoSlug} />);

      expect(screen.getByText('Gallery URL:')).toBeInTheDocument();
    });

    it('should not render when isOpen is false', () => {
      render(<WorkspaceEditModal {...defaultProps} isOpen={false} />);

      expect(HTMLDialogElement.prototype.close).not.toHaveBeenCalled();
      expect(HTMLDialogElement.prototype.showModal).not.toHaveBeenCalled();
    });

    it('should call showModal when isOpen is true', () => {
      render(<WorkspaceEditModal {...defaultProps} />);

      expect(HTMLDialogElement.prototype.showModal).toHaveBeenCalled();
    });
  });

  describe('slug validation', () => {
    it('should only allow lowercase letters, numbers, and hyphens in slug', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      const slugInput = screen.getByLabelText('Gallery URL Slug');
      await user.clear(slugInput);
      await user.type(slugInput, 'My Slug!@#');

      expect(slugInput).toHaveValue('myslug');
    });

    it('should show error for invalid slug on submit', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      const slugInput = screen.getByLabelText('Gallery URL Slug');
      await user.clear(slugInput);
      await user.type(slugInput, '-ab');

      await user.click(screen.getByText('Save'));

      expect(screen.getByText(/Slug must be 3-50 characters/)).toBeInTheDocument();
    });
  });

  describe('form submission', () => {
    it('should submit both name and slug', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      const nameInput = screen.getByDisplayValue('Test Workspace');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Workspace');

      await user.click(screen.getByText('Save'));

      await waitFor(() => {
        expect(workspacesApi.update).toHaveBeenCalledWith(1, {
          name: 'Updated Workspace',
          slug: 'test-workspace',
        });
      });
    });

    it('should send null slug when slug field is empty', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      const slugInput = screen.getByLabelText('Gallery URL Slug');
      await user.clear(slugInput);

      await user.click(screen.getByText('Save'));

      await waitFor(() => {
        expect(workspacesApi.update).toHaveBeenCalledWith(1, {
          name: 'Test Workspace',
          slug: null,
        });
      });
    });

    it('should call onSaved and onClose on success', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await user.click(screen.getByText('Save'));

      await waitFor(() => {
        expect(defaultProps.onSaved).toHaveBeenCalled();
        expect(defaultProps.onClose).toHaveBeenCalled();
      });
    });

    it('should show error when name update fails', async () => {
      vi.mocked(workspacesApi.update).mockRejectedValue(new Error('Name update failed'));

      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await user.click(screen.getByText('Save'));

      await waitFor(() => {
        expect(screen.getByText('Name update failed')).toBeInTheDocument();
      });

      expect(defaultProps.onSaved).not.toHaveBeenCalled();
      expect(defaultProps.onClose).not.toHaveBeenCalled();
    });

    it('should show error when workspace name is empty', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      const nameInput = screen.getByDisplayValue('Test Workspace');
      await user.clear(nameInput);

      expect(screen.getByText('Save')).toBeDisabled();
    });

    it('should show Saving... text while submitting', async () => {
      vi.mocked(workspacesApi.update).mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve({ workspaceId: 1, workspaceName: 'Test' }), 100))
      );

      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await user.click(screen.getByText('Save'));

      expect(screen.getByText('Saving...')).toBeInTheDocument();
    });
  });

  describe('dialog behavior', () => {
    it('should close modal when Close button clicked', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await user.click(screen.getByLabelText('Close'));

      expect(defaultProps.onClose).toHaveBeenCalled();
    });

    it('should close modal when Cancel clicked', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await user.click(screen.getByText('Cancel'));

      expect(defaultProps.onClose).toHaveBeenCalled();
    });

    it('should close modal when backdrop clicked', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      const dialog = document.querySelector('dialog');
      await user.click(dialog!);

      expect(defaultProps.onClose).toHaveBeenCalled();
    });

    it('should reset form when modal reopens with different workspace', () => {
      const { rerender } = render(<WorkspaceEditModal {...defaultProps} />);

      expect(screen.getByDisplayValue('Test Workspace')).toBeInTheDocument();
      expect(screen.getByDisplayValue('test-workspace')).toBeInTheDocument();

      const otherWorkspace: WorkspaceMembership = {
        workspaceId: 2,
        workspaceName: 'Other Workspace',
        workspaceRole: WorkspaceRole.WorkspaceAdmin,
        hasCompletedWelcome: true,
        slug: 'other-slug',
      };

      rerender(<WorkspaceEditModal {...defaultProps} workspace={otherWorkspace} />);

      expect(screen.getByDisplayValue('Other Workspace')).toBeInTheDocument();
      expect(screen.getByDisplayValue('other-slug')).toBeInTheDocument();
    });
  });

  describe('snapshots', () => {
    it('should match snapshot when open', () => {
      const { container } = render(<WorkspaceEditModal {...defaultProps} />);

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot with error', async () => {
      vi.mocked(workspacesApi.update).mockRejectedValue(new Error('Something went wrong'));

      const user = userEvent.setup();
      const { container } = render(<WorkspaceEditModal {...defaultProps} />);

      await user.click(screen.getByText('Save'));

      await waitFor(() => {
        expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      });

      expect(container).toMatchSnapshot();
    });
  });

  it('prevents every dismissal and duplicate submission while saving, retaining a failed draft for retry', async () => {
    const user = userEvent.setup();
    const pending = deferred<Awaited<ReturnType<typeof workspacesApi.update>>>();
    vi.mocked(workspacesApi.update).mockReturnValueOnce(pending.promise);
    const confirm = vi.spyOn(window, 'confirm');
    render(<WorkspaceEditModal {...defaultProps} />);
    await user.type(screen.getByRole('textbox', { name: /Workspace Name/ }), ' changed');
    const dialog = screen.getByRole('dialog', { name: 'Edit Workspace' });
    await user.click(screen.getByRole('button', { name: 'Save' }));
    fireEvent.submit(screen.getByRole('form', { name: 'Edit workspace details' }));
    expect(workspacesApi.update).toHaveBeenCalledOnce();
    for (const field of screen.getAllByRole('textbox')) expect(field).toBeDisabled();
    for (const button of screen.getAllByRole('button')) expect(button).toBeDisabled();
    const cancel = new Event('cancel', { bubbles: true, cancelable: true });
    fireEvent(dialog, cancel);
    expect(cancel.defaultPrevented).toBe(true);
    fireEvent.click(dialog);
    expect(defaultProps.onClose).not.toHaveBeenCalled();
    expect(confirm).not.toHaveBeenCalled();
    await act(async () => pending.reject(new Error('Unable to save')));
    expect(screen.getByRole('alert')).toHaveTextContent('Unable to save');
    expect(screen.getByRole('textbox', { name: /Workspace Name/ })).toHaveValue('Test Workspace changed');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(defaultProps.onSaved).toHaveBeenCalledOnce();
    expect(defaultProps.onClose).toHaveBeenCalledOnce();
  });

  it('requires confirmation for edited drafts on Escape, backdrop, Cancel and close', async () => {
    const user = userEvent.setup();
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    render(<WorkspaceEditModal {...defaultProps} />);
    await user.type(screen.getByRole('textbox', { name: 'Gallery URL Slug' }), '-new');
    fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true, bubbles: true }));
    fireEvent.click(screen.getByRole('dialog'));
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    await user.click(screen.getByRole('button', { name: 'Close' }));
    expect(defaultProps.onClose).not.toHaveBeenCalled();
    expect(confirm).toHaveBeenCalledTimes(4);
    expect(screen.getByRole('textbox', { name: 'Gallery URL Slug' })).toHaveValue('test-workspace-new');
    confirm.mockReturnValueOnce(true);
    await user.click(screen.getByRole('button', { name: 'Close' }));
    expect(defaultProps.onClose).toHaveBeenCalledOnce();
  });

  it('opens a fresh session after closing, and ignores a completed save from the previous workspace', async () => {
    const user = userEvent.setup();
    const pending = deferred<Awaited<ReturnType<typeof workspacesApi.update>>>();
    vi.mocked(workspacesApi.update).mockReturnValueOnce(pending.promise);
    const { rerender } = render(<WorkspaceEditModal {...defaultProps} />);
    await user.type(screen.getByRole('textbox', { name: /Workspace Name/ }), ' edited');
    rerender(<WorkspaceEditModal {...defaultProps} isOpen={false} />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    rerender(<WorkspaceEditModal {...defaultProps} />);
    expect(screen.getByRole('textbox', { name: /Workspace Name/ })).toHaveValue('Test Workspace');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    rerender(<WorkspaceEditModal {...defaultProps} workspace={{ ...mockWorkspace, workspaceId: 2, workspaceName: 'Other' }} />);
    await act(async () => pending.resolve({ workspaceId: 1, workspaceName: 'Test Workspace' }));
    expect(defaultProps.onSaved).not.toHaveBeenCalled();
    expect(defaultProps.onClose).not.toHaveBeenCalled();
    expect(screen.getByRole('textbox', { name: /Workspace Name/ })).toHaveValue('Other');
    rerender(<WorkspaceEditModal {...defaultProps} workspace={null} />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('supports saving without a completion listener and hides an empty gallery preview', async () => {
    const user = userEvent.setup();
    render(<WorkspaceEditModal {...defaultProps} onSaved={undefined} />);
    await user.clear(screen.getByRole('textbox', { name: 'Gallery URL Slug' }));
    expect(screen.queryByText('Gallery URL:')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(defaultProps.onClose).toHaveBeenCalledOnce();
  });
});
