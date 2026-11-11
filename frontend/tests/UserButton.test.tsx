import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import UserButton from '../src/components/user/UserButton';
import * as UserContext from '../src/contexts/useUser';
import { createMockCurrentUser } from './testUtils';
import { deferred } from './testUtils/deferred';

vi.mock('../src/contexts/useUser', () => ({
  useUser: vi.fn(),
}));

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

// Mock window.location
const mockLocation = { href: '' };
Object.defineProperty(window, 'location', {
  value: mockLocation,
  writable: true,
});

function renderWithRouter(children: React.ReactNode) {
  return render(
    <MemoryRouter>
      {children}
    </MemoryRouter>
  );
}

describe('UserButton', () => {
  const mockOnClick = vi.fn();
  const mockLogout = vi.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    vi.clearAllMocks();
    mockLocation.href = '';
  });

  it('should return null when loading', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: null,
      loading: true,
      error: null,
      signedOut: false, refetch: vi.fn(),
      logout: mockLogout,
    });

    const { container } = renderWithRouter(<UserButton onClick={mockOnClick} />);
    expect(container.firstChild).toBeNull();
  });

  it('should return null when no user', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: null,
      loading: false,
      error: null,
      signedOut: false, refetch: vi.fn(),
      logout: mockLogout,
    });

    const { container } = renderWithRouter(<UserButton onClick={mockOnClick} />);
    expect(container.firstChild).toBeNull();
  });

  it('should render settings and sign out buttons when user is logged in', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: createMockCurrentUser(),
      loading: false,
      error: null,
      signedOut: false, refetch: vi.fn(),
      logout: mockLogout,
    });

    renderWithRouter(<UserButton onClick={mockOnClick} />);
    expect(screen.getByRole('button', { name: 'Settings' })).toBeInTheDocument();
    expect(screen.getByText('Sign Out')).toBeInTheDocument();
  });

  it('should show Admin button only for system administrators', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: createMockCurrentUser({ email: 'admin@example.com', isSystemAdministrator: true }),
      loading: false,
      error: null,
      signedOut: false, refetch: vi.fn(),
      logout: mockLogout,
    });

    renderWithRouter(<UserButton onClick={mockOnClick} />);
    expect(screen.getByText('Admin')).toBeInTheDocument();
  });

  it('should not show Admin button for non-administrators', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: createMockCurrentUser({ email: 'user@example.com' }),
      loading: false,
      error: null,
      signedOut: false, refetch: vi.fn(),
      logout: mockLogout,
    });

    renderWithRouter(<UserButton onClick={mockOnClick} />);
    expect(screen.queryByText('Admin')).not.toBeInTheDocument();
  });

  it('should call logout on Sign Out click', async () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: createMockCurrentUser(),
      loading: false,
      error: null,
      signedOut: false, refetch: vi.fn(),
      logout: mockLogout,
    });

    renderWithRouter(<UserButton onClick={mockOnClick} />);

    const signOutButton = screen.getByText('Sign Out');
    await act(async () => { fireEvent.click(signOutButton); });

    expect(mockLogout).toHaveBeenCalled();
    await waitFor(() => expect(mockLocation.href).toBe('/'));
  });

  it('opens settings through its supplied action or the settings route', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({ user: createMockCurrentUser(), loading: false, error: null, signedOut: false, refetch: vi.fn(), logout: mockLogout });
    const { rerender } = renderWithRouter(<UserButton onClick={mockOnClick} />);
    fireEvent.click(screen.getByRole('button', { name: 'Settings' }));
    expect(mockOnClick).toHaveBeenCalledOnce();
    expect(mockNavigate).not.toHaveBeenCalled();
    rerender(<MemoryRouter><UserButton /></MemoryRouter>);
    fireEvent.click(screen.getByRole('button', { name: 'Settings' }));
    expect(mockNavigate).toHaveBeenCalledWith('/settings');
  });

  it('keeps failed sign-out visible and prevents duplicate submissions while retrying', async () => {
    const retry = deferred<void>();
    mockLogout.mockRejectedValueOnce(new Error('Network unavailable')).mockReturnValueOnce(retry.promise);
    vi.mocked(UserContext.useUser).mockReturnValue({ user: createMockCurrentUser(), loading: false, error: null, signedOut: false, refetch: vi.fn(), logout: mockLogout });
    renderWithRouter(<UserButton />);
    fireEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Network unavailable');
    expect(mockLocation.href).toBe('');
    fireEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
    const pending = screen.getByRole('button', { name: 'Signing out…' });
    expect(pending).toBeDisabled();
    fireEvent.click(pending);
    expect(mockLogout).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    await act(async () => retry.resolve());
    expect(mockLocation.href).toBe('/');
  });

  it('should navigate to /admin when Admin button clicked', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: createMockCurrentUser({ email: 'admin@example.com', isSystemAdministrator: true }),
      loading: false,
      error: null,
      signedOut: false, refetch: vi.fn(),
      logout: mockLogout,
    });

    renderWithRouter(<UserButton onClick={mockOnClick} />);

    const adminButton = screen.getByText('Admin');
    fireEvent.click(adminButton);

    expect(mockNavigate).toHaveBeenCalledWith('/admin');
  });

  describe('snapshots', () => {
    it('should match snapshot for regular user', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: createMockCurrentUser({ email: 'user@example.com' }),
        loading: false,
        error: null,
        signedOut: false, refetch: vi.fn(),
        logout: mockLogout,
      });

      const { container } = renderWithRouter(<UserButton onClick={mockOnClick} />);
      expect(container).toMatchSnapshot();
    });

    it('should match snapshot for admin user', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: createMockCurrentUser({ email: 'admin@example.com', isSystemAdministrator: true }),
        loading: false,
        error: null,
        signedOut: false, refetch: vi.fn(),
        logout: mockLogout,
      });

      const { container } = renderWithRouter(<UserButton onClick={mockOnClick} />);
      expect(container).toMatchSnapshot();
    });
  });
});
