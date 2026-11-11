import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import WorkspaceSwitcher from '../src/components/common/WorkspaceSwitcher';
import { useUser } from '../src/contexts/useUser';
import { workspacesApi } from '../src/api';
import type { CurrentUser, WorkspaceMembership } from '../src/utils/types';
import { WorkspaceRole } from '../src/utils/types';

vi.mock('../src/contexts/useUser', () => ({
  useUser: vi.fn(),
}));

vi.mock('../src/api', () => ({
  workspacesApi: {
    switch: vi.fn(),
  },
}));

describe('WorkspaceSwitcher', () => {
  const mockActiveWorkspace: WorkspaceMembership = {
    workspaceId: 1,
    workspaceName: 'Primary Workspace',
    workspaceRole: WorkspaceRole.WorkspaceAdmin,
    hasCompletedWelcome: true,
  };

  const mockOtherWorkspace: WorkspaceMembership = {
    workspaceId: 2,
    workspaceName: 'Secondary Workspace',
    workspaceRole: WorkspaceRole.Normal,
    hasCompletedWelcome: true,
  };

  const mockUserWithMultipleWorkspaces: CurrentUser = {
    userId: 1,
    email: 'test@example.com',
    activeWorkspace: mockActiveWorkspace,
    workspaces: [mockActiveWorkspace, mockOtherWorkspace],
    workspaceId: 1,
    workspaceName: 'Primary Workspace',
    hasCompletedWelcome: true,
    hasAcceptedTerms: true,
    isSystemAdministrator: false,
    workspaceRole: WorkspaceRole.WorkspaceAdmin,
    isWorkspaceAdmin: true,
  };

  const mockUserWithSingleWorkspace: CurrentUser = {
    ...mockUserWithMultipleWorkspaces,
    workspaces: [mockActiveWorkspace],
  };

  const mockRefetch = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders nothing when user has only one workspace', () => {
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: mockUserWithSingleWorkspace,
      signedOut: false, refetch: mockRefetch,
    });

    const { container } = render(<WorkspaceSwitcher />);
    expect(container.firstChild).toBeNull();
  });

  it('renders nothing for an account without an active workspace', () => {
    vi.mocked(useUser).mockReturnValue({ user: { ...mockUserWithMultipleWorkspaces, activeWorkspace: null, workspaceId: null, workspaces: [] },
      loading: false, error: null, signedOut: false, refetch: mockRefetch, logout: vi.fn() });
    expect(render(<WorkspaceSwitcher />).container).toBeEmptyDOMElement();
  });

  it('renders nothing when user is null', () => {
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: null,
      signedOut: false, refetch: mockRefetch,
    });

    const { container } = render(<WorkspaceSwitcher />);
    expect(container.firstChild).toBeNull();
  });

  it('renders trigger button with active workspace name', () => {
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: mockUserWithMultipleWorkspaces,
      signedOut: false, refetch: mockRefetch,
    });

    render(<WorkspaceSwitcher />);
    expect(screen.getByRole('button', { name: /primary workspace/i })).toBeInTheDocument();
  });

  it('renders the native popover contents', async () => {
    const user = userEvent.setup();
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: mockUserWithMultipleWorkspaces,
      signedOut: false, refetch: mockRefetch,
    });

    render(<WorkspaceSwitcher />);

    await user.click(screen.getByRole('button', { name: /primary workspace/i }));

    expect(document.querySelector('[popover=auto]')).toBeInTheDocument();
    expect(screen.getByText('Current')).toBeInTheDocument();
    expect(screen.getByText('Switch to')).toBeInTheDocument();
  });

  it('shows other workspaces in dropdown', async () => {
    const user = userEvent.setup();
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: mockUserWithMultipleWorkspaces,
      signedOut: false, refetch: mockRefetch,
    });

    render(<WorkspaceSwitcher />);

    await user.click(screen.getByRole('button', { name: /primary workspace/i }));

    expect(screen.getByText('Secondary Workspace')).toBeInTheDocument();
    expect(screen.getByText('Member')).toBeInTheDocument();
  });

  it('calls switch API when other workspace is clicked', async () => {
    const user = userEvent.setup();
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: mockUserWithMultipleWorkspaces,
      signedOut: false, refetch: mockRefetch,
    });
    (workspacesApi.switch as ReturnType<typeof vi.fn>).mockResolvedValue({
      success: true,
      workspaceId: 2,
      workspaceName: 'Secondary Workspace',
    });

    // Switching refreshes the session instead of forcing a full-page reload.
    const reloadMock = vi.fn();
    Object.defineProperty(window, 'location', {
      value: { reload: reloadMock },
      writable: true,
    });

    render(<WorkspaceSwitcher />);

    await user.click(screen.getByRole('button', { name: /primary workspace/i }));
    await user.click(screen.getByRole('button', { name: /secondary workspace/i, hidden: true }));

    expect(workspacesApi.switch).toHaveBeenCalledWith(2);
    expect(mockRefetch).toHaveBeenCalledWith({ throwOnError: true });
    expect(reloadMock).not.toHaveBeenCalled();
  });

  it('associates the trigger with an automatically dismissed native popover', () => {
    vi.mocked(useUser).mockReturnValue({ user: mockUserWithMultipleWorkspaces, signedOut: false, refetch: mockRefetch } as unknown as ReturnType<typeof useUser>);
    render(<WorkspaceSwitcher />);
    const trigger = screen.getByRole('button', { name: /primary workspace/i });
    const popover = document.getElementById(trigger.getAttribute('popovertarget')!);
    expect(popover).toHaveAttribute('popover', 'auto');
  });

  it('handles switch error gracefully', async () => {
    const user = userEvent.setup();
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: mockUserWithMultipleWorkspaces,
      signedOut: false, refetch: mockRefetch,
    });
    (workspacesApi.switch as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Switch failed'));

    render(<WorkspaceSwitcher />);

    await user.click(screen.getByRole('button', { name: /primary workspace/i }));
    await user.click(screen.getByRole('button', { name: /secondary workspace/i, hidden: true }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Switch failed');
      expect(mockRefetch).toHaveBeenCalled();
    });
  });

  it('shows each membership role and treats an unsuccessful switch response as an error', async () => {
    const activeWorkspace = { ...mockActiveWorkspace, workspaceRole: WorkspaceRole.Normal };
    const destination = { ...mockOtherWorkspace, workspaceRole: WorkspaceRole.WorkspaceAdmin };
    vi.mocked(useUser).mockReturnValue({ user: { ...mockUserWithMultipleWorkspaces, activeWorkspace, workspaces: [activeWorkspace, destination] }, refetch: mockRefetch } as unknown as ReturnType<typeof useUser>);
    vi.mocked(workspacesApi.switch).mockResolvedValue({ success: false, workspaceId: 1, workspaceName: 'Primary Workspace' });
    render(<WorkspaceSwitcher />);
    expect(document.querySelector('.workspace-switcher__current')).toHaveTextContent('Member');
    const button = screen.getByRole('button', { name: /Secondary Workspace Admin/, hidden: true });
    await userEvent.click(button);
    expect(screen.getByRole('alert')).toHaveTextContent('Unable to switch workspace');
    expect(mockRefetch).toHaveBeenCalledExactlyOnceWith({ throwOnError: true });
  });
});
