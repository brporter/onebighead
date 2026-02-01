import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import TenantSwitcher from '../src/components/common/TenantSwitcher';
import { useUser } from '../src/contexts/UserContext';
import { tenantsApi } from '../src/api';
import type { CurrentUser, TenantMembership } from '../src/utils/types';
import { TenantRole } from '../src/utils/types';

vi.mock('../src/contexts/UserContext', () => ({
  useUser: vi.fn(),
}));

vi.mock('../src/api', () => ({
  tenantsApi: {
    switch: vi.fn(),
  },
}));

describe('TenantSwitcher', () => {
  const mockActiveTenant: TenantMembership = {
    tenantId: 1,
    tenantName: 'Primary Tenant',
    tenantRole: TenantRole.TenantAdmin,
    hasCompletedWelcome: true,
  };

  const mockOtherTenant: TenantMembership = {
    tenantId: 2,
    tenantName: 'Secondary Tenant',
    tenantRole: TenantRole.Normal,
    hasCompletedWelcome: true,
  };

  const mockUserWithMultipleTenants: CurrentUser = {
    userId: 1,
    email: 'test@example.com',
    activeTenant: mockActiveTenant,
    tenants: [mockActiveTenant, mockOtherTenant],
    tenantId: 1,
    tenantName: 'Primary Tenant',
    hasCompletedWelcome: true,
    hasAcceptedTerms: true,
    isSystemAdministrator: false,
    tenantRole: 'TenantAdmin',
    isTenantAdmin: true,
  };

  const mockUserWithSingleTenant: CurrentUser = {
    ...mockUserWithMultipleTenants,
    tenants: [mockActiveTenant],
  };

  const mockRefetch = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders nothing when user has only one tenant', () => {
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: mockUserWithSingleTenant,
      refetch: mockRefetch,
    });

    const { container } = render(<TenantSwitcher />);
    expect(container.firstChild).toBeNull();
  });

  it('renders nothing when user is null', () => {
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: null,
      refetch: mockRefetch,
    });

    const { container } = render(<TenantSwitcher />);
    expect(container.firstChild).toBeNull();
  });

  it('renders trigger button with active tenant name', () => {
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: mockUserWithMultipleTenants,
      refetch: mockRefetch,
    });

    render(<TenantSwitcher />);
    expect(screen.getByText('Primary Tenant')).toBeInTheDocument();
  });

  it('opens dropdown when trigger is clicked', async () => {
    const user = userEvent.setup();
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: mockUserWithMultipleTenants,
      refetch: mockRefetch,
    });

    render(<TenantSwitcher />);

    await user.click(screen.getByRole('button', { name: /primary tenant/i }));

    expect(screen.getByRole('listbox')).toBeInTheDocument();
    expect(screen.getByText('Current')).toBeInTheDocument();
    expect(screen.getByText('Switch to')).toBeInTheDocument();
  });

  it('shows other tenants in dropdown', async () => {
    const user = userEvent.setup();
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: mockUserWithMultipleTenants,
      refetch: mockRefetch,
    });

    render(<TenantSwitcher />);

    await user.click(screen.getByRole('button', { name: /primary tenant/i }));

    expect(screen.getByText('Secondary Tenant')).toBeInTheDocument();
    expect(screen.getByText('Member')).toBeInTheDocument();
  });

  it('calls switch API when other tenant is clicked', async () => {
    const user = userEvent.setup();
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: mockUserWithMultipleTenants,
      refetch: mockRefetch,
    });
    (tenantsApi.switch as ReturnType<typeof vi.fn>).mockResolvedValue({
      success: true,
      tenantId: 2,
      tenantName: 'Secondary Tenant',
    });

    // Mock window.location.reload
    const reloadMock = vi.fn();
    Object.defineProperty(window, 'location', {
      value: { reload: reloadMock },
      writable: true,
    });

    render(<TenantSwitcher />);

    await user.click(screen.getByRole('button', { name: /primary tenant/i }));
    await user.click(screen.getByRole('option', { name: /secondary tenant/i }));

    expect(tenantsApi.switch).toHaveBeenCalledWith(2);
  });

  it('closes dropdown when clicking outside', async () => {
    const user = userEvent.setup();
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: mockUserWithMultipleTenants,
      refetch: mockRefetch,
    });

    render(
      <div>
        <div data-testid="outside">Outside</div>
        <TenantSwitcher />
      </div>
    );

    // Open dropdown
    await user.click(screen.getByRole('button', { name: /primary tenant/i }));
    expect(screen.getByRole('listbox')).toBeInTheDocument();

    // Click outside
    fireEvent.mouseDown(screen.getByTestId('outside'));

    await waitFor(() => {
      expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    });
  });

  it('handles switch error gracefully', async () => {
    const user = userEvent.setup();
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
    (useUser as ReturnType<typeof vi.fn>).mockReturnValue({
      user: mockUserWithMultipleTenants,
      refetch: mockRefetch,
    });
    (tenantsApi.switch as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Switch failed'));

    render(<TenantSwitcher />);

    await user.click(screen.getByRole('button', { name: /primary tenant/i }));
    await user.click(screen.getByRole('option', { name: /secondary tenant/i }));

    await waitFor(() => {
      expect(consoleError).toHaveBeenCalled();
      expect(mockRefetch).toHaveBeenCalled();
    });

    consoleError.mockRestore();
  });
});
