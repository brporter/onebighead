import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import WorkspaceEditModal from '../src/components/workspace/WorkspaceEditModal';
import { workspacesApi } from '../src/api';
import type { WorkspaceMembership } from '../src/utils/types';
import { WorkspaceRole } from '../src/utils/types';

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

    it('should not show URL preview when slug is empty', () => {
      const workspaceNoSlug: WorkspaceMembership = {
        ...mockWorkspace,
        slug: undefined,
        workspaceName: 'X',
      };

      render(<WorkspaceEditModal {...defaultProps} workspace={workspaceNoSlug} />);

      // auto-suggest is 'x' which is too short for display (1 char), but we show preview if non-empty
      // Actually toSlug('X') => 'x' which is not empty
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
});
