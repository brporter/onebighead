import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import UserManagement from '../src/components/user/UserManagement';
import * as UserContext from '../src/contexts/UserContext';
import * as usersApiModule from '../src/api/users';
import type { TenantUser } from '../src/utils/types';
import { TenantRole } from '../src/utils/types';

vi.mock('../src/contexts/UserContext', () => ({
  useUser: vi.fn(),
}));

vi.mock('../src/api/users', () => ({
  usersApi: {
    getUsers: vi.fn(),
    inviteUser: vi.fn(),
    updateUserRole: vi.fn(),
    removeUser: vi.fn(),
  },
}));

// Mock window.alert and window.confirm
const mockAlert = vi.fn();
const mockConfirm = vi.fn();
window.alert = mockAlert;
window.confirm = mockConfirm;

describe('UserManagement', () => {
  const mockCurrentUser = {
    userId: 1,
    email: 'admin@example.com',
    tenantId: 1,
    tenantName: 'Test Tenant',
    hasCompletedWelcome: true,
    isSystemAdministrator: false,
    tenantRole: TenantRole.TenantAdmin,
    isTenantAdmin: true,
  };

  const mockUsers: TenantUser[] = [
    {
      userId: 1,
      email: 'admin@example.com',
      tenantRole: TenantRole.TenantAdmin,
      isLinked: true,
      identityProvider: 'Microsoft',
      createdAt: '2024-01-01T00:00:00Z',
    },
    {
      userId: 2,
      email: 'member@example.com',
      tenantRole: TenantRole.Normal,
      isLinked: true,
      identityProvider: 'Google',
      createdAt: '2024-01-02T00:00:00Z',
    },
    {
      userId: 3,
      email: 'pending@example.com',
      tenantRole: TenantRole.Normal,
      isLinked: false,
      identityProvider: null,
      createdAt: '2024-01-03T00:00:00Z',
    },
  ];

  const mockOnDirtyChange = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    mockConfirm.mockReturnValue(true);

    vi.mocked(UserContext.useUser).mockReturnValue({
      user: mockCurrentUser,
      loading: false,
      error: null,
      refetch: vi.fn(),
      logout: vi.fn(),
    });

    vi.mocked(usersApiModule.usersApi.getUsers).mockResolvedValue(mockUsers);
    vi.mocked(usersApiModule.usersApi.inviteUser).mockResolvedValue({
      userId: 4,
      email: 'new@example.com',
      tenantRole: TenantRole.Normal,
      isLinked: false,
      identityProvider: null,
      createdAt: '2024-01-04T00:00:00Z',
    });
    vi.mocked(usersApiModule.usersApi.updateUserRole).mockResolvedValue(undefined);
    vi.mocked(usersApiModule.usersApi.removeUser).mockResolvedValue(undefined);
  });

  describe('loading state', () => {
    it('should show loading state initially', () => {
      vi.mocked(usersApiModule.usersApi.getUsers).mockImplementation(
        () => new Promise(() => {}) // Never resolves
      );

      render(<UserManagement />);

      expect(screen.getByText('Loading team members...')).toBeInTheDocument();
    });

    it('should load and display users', async () => {
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('admin@example.com')).toBeInTheDocument();
      });

      expect(screen.getByText('member@example.com')).toBeInTheDocument();
      expect(screen.getByText('pending@example.com')).toBeInTheDocument();
    });
  });

  describe('error handling', () => {
    it('should display error when loading fails', async () => {
      vi.mocked(usersApiModule.usersApi.getUsers).mockRejectedValue(new Error('Network error'));

      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('Network error')).toBeInTheDocument();
      });
    });

    it('should display generic error for non-Error exceptions', async () => {
      vi.mocked(usersApiModule.usersApi.getUsers).mockRejectedValue('Unknown error');

      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('Failed to load team members')).toBeInTheDocument();
      });
    });
  });

  describe('user list display', () => {
    it('should show "You" badge for current user', async () => {
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('You')).toBeInTheDocument();
      });
    });

    it('should show "Pending" badge for unlinked users', async () => {
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('Pending')).toBeInTheDocument();
      });
    });

    it('should show "Active" badge for linked users', async () => {
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getAllByText('Active').length).toBe(2);
      });
    });

    it('should show identity provider for linked users', async () => {
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('Microsoft')).toBeInTheDocument();
        expect(screen.getByText('Google')).toBeInTheDocument();
      });
    });

    it('should disable controls for current user', async () => {
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('admin@example.com')).toBeInTheDocument();
      });

      // Find the role select for the current user (first user)
      const roleSelects = screen.getAllByRole('combobox');
      expect(roleSelects[1]).toBeDisabled(); // First user's role select (after invite role)

      // Find the remove button for the current user
      const removeButtons = screen.getAllByText('Remove');
      expect(removeButtons[0]).toBeDisabled();
    });
  });

  describe('invite user', () => {
    it('should invite user when form is submitted', async () => {
      const user = userEvent.setup();
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByPlaceholderText('Enter email address')).toBeInTheDocument();
      });

      const emailInput = screen.getByPlaceholderText('Enter email address');
      const inviteButton = screen.getByRole('button', { name: 'Invite' });

      await user.type(emailInput, 'new@example.com');
      await user.click(inviteButton);

      await waitFor(() => {
        expect(usersApiModule.usersApi.inviteUser).toHaveBeenCalledWith({
          email: 'new@example.com',
          role: TenantRole.Normal,
        });
      });
    });

    it('should invite user as admin when selected', async () => {
      const user = userEvent.setup();
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByPlaceholderText('Enter email address')).toBeInTheDocument();
      });

      const emailInput = screen.getByPlaceholderText('Enter email address');
      const roleSelect = screen.getAllByRole('combobox')[0]; // First combobox is invite role
      const inviteButton = screen.getByRole('button', { name: 'Invite' });

      await user.type(emailInput, 'newadmin@example.com');
      await user.selectOptions(roleSelect, 'TenantAdmin');
      await user.click(inviteButton);

      await waitFor(() => {
        expect(usersApiModule.usersApi.inviteUser).toHaveBeenCalledWith({
          email: 'newadmin@example.com',
          role: TenantRole.TenantAdmin,
        });
      });
    });

    it('should clear form after successful invite', async () => {
      const user = userEvent.setup();
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByPlaceholderText('Enter email address')).toBeInTheDocument();
      });

      const emailInput = screen.getByPlaceholderText('Enter email address') as HTMLInputElement;
      const inviteButton = screen.getByRole('button', { name: 'Invite' });

      await user.type(emailInput, 'new@example.com');
      await user.click(inviteButton);

      await waitFor(() => {
        expect(emailInput.value).toBe('');
      });
    });

    it('should show error when invite fails', async () => {
      vi.mocked(usersApiModule.usersApi.inviteUser).mockRejectedValue(new Error('Email already exists'));

      const user = userEvent.setup();
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByPlaceholderText('Enter email address')).toBeInTheDocument();
      });

      const emailInput = screen.getByPlaceholderText('Enter email address');
      const inviteButton = screen.getByRole('button', { name: 'Invite' });

      await user.type(emailInput, 'existing@example.com');
      await user.click(inviteButton);

      await waitFor(() => {
        expect(screen.getByText('Email already exists')).toBeInTheDocument();
      });
    });

    it('should disable invite button when email is empty', async () => {
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Invite' })).toBeDisabled();
      });
    });

    it('should call onDirtyChange when email changes', async () => {
      const user = userEvent.setup();
      render(<UserManagement onDirtyChange={mockOnDirtyChange} />);

      await waitFor(() => {
        expect(screen.getByPlaceholderText('Enter email address')).toBeInTheDocument();
      });

      const emailInput = screen.getByPlaceholderText('Enter email address');
      await user.type(emailInput, 'test@example.com');

      await waitFor(() => {
        expect(mockOnDirtyChange).toHaveBeenCalledWith(true);
      });
    });
  });

  describe('change user role', () => {
    it('should update user role', async () => {
      const user = userEvent.setup();
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('member@example.com')).toBeInTheDocument();
      });

      // Find the role select for the second user (member)
      const roleSelects = screen.getAllByRole('combobox');
      const memberRoleSelect = roleSelects[2]; // Skip invite role and admin role

      await user.selectOptions(memberRoleSelect, 'TenantAdmin');

      await waitFor(() => {
        expect(usersApiModule.usersApi.updateUserRole).toHaveBeenCalledWith(2, TenantRole.TenantAdmin);
      });
    });

    it('should prevent demoting last admin', async () => {
      // Set up scenario with only one admin
      const singleAdminUsers: TenantUser[] = [
        {
          userId: 1,
          email: 'admin@example.com',
          tenantRole: TenantRole.TenantAdmin,
          isLinked: true,
          identityProvider: 'Microsoft',
          createdAt: '2024-01-01T00:00:00Z',
        },
        {
          userId: 2,
          email: 'member@example.com',
          tenantRole: TenantRole.Normal,
          isLinked: true,
          identityProvider: 'Google',
          createdAt: '2024-01-02T00:00:00Z',
        },
      ];

      // Update current user to be user 2 so we can try to demote user 1
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: { ...mockCurrentUser, userId: 2 },
        loading: false,
        error: null,
        refetch: vi.fn(),
        logout: vi.fn(),
      });

      vi.mocked(usersApiModule.usersApi.getUsers).mockResolvedValue(singleAdminUsers);

      const user = userEvent.setup();
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('admin@example.com')).toBeInTheDocument();
      });

      // Try to demote the only admin
      const roleSelects = screen.getAllByRole('combobox');
      const adminRoleSelect = roleSelects[1]; // First user's role select

      await user.selectOptions(adminRoleSelect, 'Normal');

      expect(mockAlert).toHaveBeenCalledWith('Cannot demote the last admin. Promote another user first.');
      expect(usersApiModule.usersApi.updateUserRole).not.toHaveBeenCalled();
    });

    it('should show error when role update fails', async () => {
      vi.mocked(usersApiModule.usersApi.updateUserRole).mockRejectedValue(new Error('Update failed'));

      const user = userEvent.setup();
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('member@example.com')).toBeInTheDocument();
      });

      const roleSelects = screen.getAllByRole('combobox');
      const memberRoleSelect = roleSelects[2];

      await user.selectOptions(memberRoleSelect, 'TenantAdmin');

      await waitFor(() => {
        expect(screen.getByText('Update failed')).toBeInTheDocument();
      });
    });
  });

  describe('remove user', () => {
    it('should remove user when confirmed', async () => {
      const user = userEvent.setup();
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('member@example.com')).toBeInTheDocument();
      });

      const removeButtons = screen.getAllByText('Remove');
      await user.click(removeButtons[1]); // Second remove button (member)

      await waitFor(() => {
        expect(usersApiModule.usersApi.removeUser).toHaveBeenCalledWith(2);
      });
    });

    it('should show different confirm message for pending users', async () => {
      const user = userEvent.setup();
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('pending@example.com')).toBeInTheDocument();
      });

      const removeButtons = screen.getAllByText('Remove');
      await user.click(removeButtons[2]); // Third remove button (pending)

      expect(mockConfirm).toHaveBeenCalledWith(
        'Are you sure you want to cancel the invitation for pending@example.com?'
      );
    });

    it('should show different confirm message for linked users', async () => {
      const user = userEvent.setup();
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('member@example.com')).toBeInTheDocument();
      });

      const removeButtons = screen.getAllByText('Remove');
      await user.click(removeButtons[1]); // Second remove button (member)

      expect(mockConfirm).toHaveBeenCalledWith(
        'Are you sure you want to remove member@example.com from the team? They will no longer have access.'
      );
    });

    it('should not remove user when cancelled', async () => {
      mockConfirm.mockReturnValue(false);

      const user = userEvent.setup();
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('member@example.com')).toBeInTheDocument();
      });

      const removeButtons = screen.getAllByText('Remove');
      await user.click(removeButtons[1]);

      expect(usersApiModule.usersApi.removeUser).not.toHaveBeenCalled();
    });

    it('should prevent removing last admin', async () => {
      // Set up scenario with only one admin
      const singleAdminUsers: TenantUser[] = [
        {
          userId: 1,
          email: 'admin@example.com',
          tenantRole: TenantRole.TenantAdmin,
          isLinked: true,
          identityProvider: 'Microsoft',
          createdAt: '2024-01-01T00:00:00Z',
        },
      ];

      // Make current user different so they can try to remove the admin
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: { ...mockCurrentUser, userId: 999 },
        loading: false,
        error: null,
        refetch: vi.fn(),
        logout: vi.fn(),
      });

      vi.mocked(usersApiModule.usersApi.getUsers).mockResolvedValue(singleAdminUsers);

      const user = userEvent.setup();
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('admin@example.com')).toBeInTheDocument();
      });

      const removeButton = screen.getByText('Remove');
      await user.click(removeButton);

      expect(mockAlert).toHaveBeenCalledWith('Cannot remove the last admin. Promote another user first.');
      expect(usersApiModule.usersApi.removeUser).not.toHaveBeenCalled();
    });

    it('should show error when remove fails', async () => {
      vi.mocked(usersApiModule.usersApi.removeUser).mockRejectedValue(new Error('Remove failed'));

      const user = userEvent.setup();
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('member@example.com')).toBeInTheDocument();
      });

      const removeButtons = screen.getAllByText('Remove');
      await user.click(removeButtons[1]);

      await waitFor(() => {
        expect(screen.getByText('Remove failed')).toBeInTheDocument();
      });
    });
  });

  describe('legend', () => {
    it('should display role descriptions', async () => {
      render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText(/Can create collections, templates, invite users, and export data/)).toBeInTheDocument();
        expect(screen.getByText(/Can create and edit items and categories/)).toBeInTheDocument();
      });
    });
  });

  describe('snapshots', () => {
    it('should match snapshot with users loaded', async () => {
      const { container } = render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('admin@example.com')).toBeInTheDocument();
      });

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot while loading', () => {
      vi.mocked(usersApiModule.usersApi.getUsers).mockImplementation(
        () => new Promise(() => {})
      );

      const { container } = render(<UserManagement />);

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot with error', async () => {
      vi.mocked(usersApiModule.usersApi.getUsers).mockRejectedValue(new Error('Failed to load'));

      const { container } = render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('Failed to load')).toBeInTheDocument();
      });

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot with pending user', async () => {
      const pendingOnlyUsers: TenantUser[] = [
        {
          userId: 1,
          email: 'pending@example.com',
          tenantRole: TenantRole.Normal,
          isLinked: false,
          identityProvider: null,
          createdAt: '2024-01-01T00:00:00Z',
        },
      ];

      vi.mocked(usersApiModule.usersApi.getUsers).mockResolvedValue(pendingOnlyUsers);
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: { ...mockCurrentUser, userId: 999 },
        loading: false,
        error: null,
        refetch: vi.fn(),
        logout: vi.fn(),
      });

      const { container } = render(<UserManagement />);

      await waitFor(() => {
        expect(screen.getByText('pending@example.com')).toBeInTheDocument();
      });

      expect(container).toMatchSnapshot();
    });
  });
});
