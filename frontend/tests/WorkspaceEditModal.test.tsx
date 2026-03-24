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
    getPublicAccess: vi.fn(),
    updatePublicAccess: vi.fn(),
  },
}));

describe('WorkspaceEditModal', () => {
  const mockWorkspace: WorkspaceMembership = {
    workspaceId: 1,
    workspaceName: 'Test Workspace',
    workspaceRole: WorkspaceRole.WorkspaceAdmin,
    hasCompletedWelcome: true,
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

    vi.mocked(workspacesApi.getPublicAccess).mockResolvedValue({
      workspaceId: 1,
      slug: 'test-workspace',
      isPublicAccessEnabled: false,
      publicUrl: null,
    });
    vi.mocked(workspacesApi.update).mockResolvedValue({
      workspaceId: 1,
      workspaceName: 'Test Workspace',
    });
    vi.mocked(workspacesApi.updatePublicAccess).mockResolvedValue({
      workspaceId: 1,
      slug: 'test-workspace',
      isPublicAccessEnabled: false,
      publicUrl: null,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('rendering', () => {
    it('should render the modal with workspace name', async () => {
      render(<WorkspaceEditModal {...defaultProps} />);

      expect(screen.getByText('Edit Workspace')).toBeInTheDocument();
      expect(screen.getByDisplayValue('Test Workspace')).toBeInTheDocument();
    });

    it('should render public access fields after loading', async () => {
      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('Public Access')).toBeInTheDocument();
      });

      expect(screen.getByLabelText('Public URL Slug')).toBeInTheDocument();
      expect(screen.getByText('Enable Public Access')).toBeInTheDocument();
    });

    it('should show loading message while public access is loading', () => {
      vi.mocked(workspacesApi.getPublicAccess).mockImplementation(
        () => new Promise(() => {})
      );

      render(<WorkspaceEditModal {...defaultProps} />);

      expect(screen.getByText('Loading public access settings...')).toBeInTheDocument();
    });

    it('should not render when isOpen is false', () => {
      render(<WorkspaceEditModal {...defaultProps} isOpen={false} />);

      expect(HTMLDialogElement.prototype.close).toHaveBeenCalled();
    });

    it('should call showModal when isOpen is true', () => {
      render(<WorkspaceEditModal {...defaultProps} />);

      expect(HTMLDialogElement.prototype.showModal).toHaveBeenCalled();
    });
  });

  describe('loading public access data', () => {
    it('should load public access data on open', async () => {
      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(workspacesApi.getPublicAccess).toHaveBeenCalledWith(1);
      });
    });

    it('should populate slug from API response', async () => {
      vi.mocked(workspacesApi.getPublicAccess).mockResolvedValue({
        workspaceId: 1,
        slug: 'my-slug',
        isPublicAccessEnabled: true,
        publicUrl: '/public/my-slug',
      });

      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('my-slug')).toBeInTheDocument();
      });
    });

    it('should auto-suggest slug from workspace name on API error', async () => {
      vi.mocked(workspacesApi.getPublicAccess).mockRejectedValue(new Error('Not found'));

      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('test-workspace')).toBeInTheDocument();
      });
    });

    it('should show URL preview when public access is enabled', async () => {
      vi.mocked(workspacesApi.getPublicAccess).mockResolvedValue({
        workspaceId: 1,
        slug: 'my-slug',
        isPublicAccessEnabled: true,
        publicUrl: '/public/my-slug',
      });

      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('Public URL:')).toBeInTheDocument();
        expect(screen.getByText('/public/my-slug')).toBeInTheDocument();
      });
    });

    it('should not show URL preview when public access is disabled', async () => {
      vi.mocked(workspacesApi.getPublicAccess).mockResolvedValue({
        workspaceId: 1,
        slug: 'my-slug',
        isPublicAccessEnabled: false,
        publicUrl: null,
      });

      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('my-slug')).toBeInTheDocument();
      });

      expect(screen.queryByText('Public URL:')).not.toBeInTheDocument();
    });
  });

  describe('slug validation', () => {
    it('should only allow lowercase letters, numbers, and hyphens in slug', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByLabelText('Public URL Slug')).toBeInTheDocument();
      });

      const slugInput = screen.getByLabelText('Public URL Slug');
      await user.clear(slugInput);
      await user.type(slugInput, 'My Slug!@#');

      expect(slugInput).toHaveValue('myslug');
    });

    it('should show error for invalid slug on submit', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByLabelText('Public URL Slug')).toBeInTheDocument();
      });

      const slugInput = screen.getByLabelText('Public URL Slug');
      await user.clear(slugInput);
      await user.type(slugInput, 'ab');

      // Enable public access
      // Checkbox should be disabled since slug is too short to be valid
      // But we need the checkbox to be enabled - let's use a valid-looking but invalid slug
      await user.clear(slugInput);
      await user.type(slugInput, '-ab');

      // Try to save
      await user.click(screen.getByText('Save'));

      expect(screen.getByText(/Slug must be 3-50 characters/)).toBeInTheDocument();
    });

    it('should show error when public access enabled without slug', async () => {
      vi.mocked(workspacesApi.getPublicAccess).mockResolvedValue({
        workspaceId: 1,
        slug: 'valid-slug',
        isPublicAccessEnabled: false,
        publicUrl: null,
      });

      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('valid-slug')).toBeInTheDocument();
      });

      // Enable public access
      const checkbox = screen.getByRole('checkbox');
      await user.click(checkbox);

      // Clear the slug
      const slugInput = screen.getByLabelText('Public URL Slug');
      await user.clear(slugInput);

      await user.click(screen.getByText('Save'));

      expect(screen.getByText('A URL slug is required to enable public access.')).toBeInTheDocument();
    });

    it('should disable checkbox when slug is empty', async () => {
      vi.mocked(workspacesApi.getPublicAccess).mockResolvedValue({
        workspaceId: 1,
        slug: null,
        isPublicAccessEnabled: false,
        publicUrl: null,
      });

      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByRole('checkbox')).toBeDisabled();
      });

      expect(screen.getByText('Set a slug above to enable public access.')).toBeInTheDocument();
    });
  });

  describe('form submission', () => {
    it('should submit both name and public access changes', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('test-workspace')).toBeInTheDocument();
      });

      // Update name
      const nameInput = screen.getByDisplayValue('Test Workspace');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Workspace');

      // Save
      await user.click(screen.getByText('Save'));

      await waitFor(() => {
        expect(workspacesApi.update).toHaveBeenCalledWith(1, { name: 'Updated Workspace' });
        expect(workspacesApi.updatePublicAccess).toHaveBeenCalledWith(1, {
          slug: 'test-workspace',
          isPublicAccessEnabled: false,
        });
      });
    });

    it('should call onSaved and onClose on success', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('test-workspace')).toBeInTheDocument();
      });

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

      await waitFor(() => {
        expect(screen.getByDisplayValue('test-workspace')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Save'));

      await waitFor(() => {
        expect(screen.getByText('Name update failed')).toBeInTheDocument();
      });

      expect(defaultProps.onSaved).not.toHaveBeenCalled();
      expect(defaultProps.onClose).not.toHaveBeenCalled();
    });

    it('should show error when public access update fails', async () => {
      vi.mocked(workspacesApi.updatePublicAccess).mockRejectedValue(new Error('Public access update failed'));

      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('test-workspace')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Save'));

      await waitFor(() => {
        expect(screen.getByText('Public access update failed')).toBeInTheDocument();
      });

      expect(defaultProps.onSaved).not.toHaveBeenCalled();
      expect(defaultProps.onClose).not.toHaveBeenCalled();
    });

    it('should show error when workspace name is empty', async () => {
      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('test-workspace')).toBeInTheDocument();
      });

      const nameInput = screen.getByDisplayValue('Test Workspace');
      await user.clear(nameInput);

      // The save button should be disabled when name is empty
      expect(screen.getByText('Save')).toBeDisabled();
    });

    it('should show Saving... text while submitting', async () => {
      vi.mocked(workspacesApi.update).mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve({ workspaceId: 1, workspaceName: 'Test' }), 100))
      );

      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('test-workspace')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Save'));

      expect(screen.getByText('Saving...')).toBeInTheDocument();
    });

    it('should send null slug when slug is empty', async () => {
      vi.mocked(workspacesApi.getPublicAccess).mockResolvedValue({
        workspaceId: 1,
        slug: null,
        isPublicAccessEnabled: false,
        publicUrl: null,
      });

      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByRole('checkbox')).toBeDisabled();
      });

      await user.click(screen.getByText('Save'));

      await waitFor(() => {
        expect(workspacesApi.updatePublicAccess).toHaveBeenCalledWith(1, {
          slug: null,
          isPublicAccessEnabled: false,
        });
      });
    });
  });

  describe('checkbox interaction', () => {
    it('should toggle public access checkbox', async () => {
      vi.mocked(workspacesApi.getPublicAccess).mockResolvedValue({
        workspaceId: 1,
        slug: 'valid-slug',
        isPublicAccessEnabled: false,
        publicUrl: null,
      });

      const user = userEvent.setup();
      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('valid-slug')).toBeInTheDocument();
      });

      const checkbox = screen.getByRole('checkbox');
      expect(checkbox).not.toBeChecked();

      await user.click(checkbox);

      expect(checkbox).toBeChecked();
      // URL preview should appear
      expect(screen.getByText('/public/valid-slug')).toBeInTheDocument();
    });

    it('should enable checkbox when slug is provided', async () => {
      vi.mocked(workspacesApi.getPublicAccess).mockResolvedValue({
        workspaceId: 1,
        slug: 'valid-slug',
        isPublicAccessEnabled: false,
        publicUrl: null,
      });

      render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByRole('checkbox')).not.toBeDisabled();
      });
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

    it('should reset form when modal reopens with different workspace', async () => {
      const { rerender } = render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('Test Workspace')).toBeInTheDocument();
      });

      const otherWorkspace: WorkspaceMembership = {
        workspaceId: 2,
        workspaceName: 'Other Workspace',
        workspaceRole: WorkspaceRole.WorkspaceAdmin,
        hasCompletedWelcome: true,
      };

      vi.mocked(workspacesApi.getPublicAccess).mockResolvedValue({
        workspaceId: 2,
        slug: 'other-slug',
        isPublicAccessEnabled: true,
        publicUrl: '/public/other-slug',
      });

      rerender(<WorkspaceEditModal {...defaultProps} workspace={otherWorkspace} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('Other Workspace')).toBeInTheDocument();
        expect(screen.getByDisplayValue('other-slug')).toBeInTheDocument();
      });
    });
  });

  describe('snapshots', () => {
    it('should match snapshot when open', async () => {
      const { container } = render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('test-workspace')).toBeInTheDocument();
      });

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot with public access enabled', async () => {
      vi.mocked(workspacesApi.getPublicAccess).mockResolvedValue({
        workspaceId: 1,
        slug: 'my-workspace',
        isPublicAccessEnabled: true,
        publicUrl: '/public/my-workspace',
      });

      const { container } = render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('/public/my-workspace')).toBeInTheDocument();
      });

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot with error', async () => {
      vi.mocked(workspacesApi.update).mockRejectedValue(new Error('Something went wrong'));

      const user = userEvent.setup();
      const { container } = render(<WorkspaceEditModal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('test-workspace')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Save'));

      await waitFor(() => {
        expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      });

      expect(container).toMatchSnapshot();
    });
  });
});
