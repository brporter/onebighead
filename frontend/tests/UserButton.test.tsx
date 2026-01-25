import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import UserButton from '../src/UserButton';
import * as UserContext from '../src/UserContext';

vi.mock('../src/UserContext', () => ({
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
      refetch: vi.fn(),
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
      refetch: vi.fn(),
      logout: mockLogout,
    });

    const { container } = renderWithRouter(<UserButton onClick={mockOnClick} />);
    expect(container.firstChild).toBeNull();
  });

  it('should render email when user is logged in', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: { userId: 1, email: 'test@example.com', tenantId: 1, isSystemAdministrator: false },
      loading: false,
      error: null,
      refetch: vi.fn(),
      logout: mockLogout,
    });

    renderWithRouter(<UserButton onClick={mockOnClick} />);
    expect(screen.getByText('test@example.com')).toBeInTheDocument();
  });

  it('should show Admin button only for system administrators', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: { userId: 1, email: 'admin@example.com', tenantId: 1, isSystemAdministrator: true },
      loading: false,
      error: null,
      refetch: vi.fn(),
      logout: mockLogout,
    });

    renderWithRouter(<UserButton onClick={mockOnClick} />);
    expect(screen.getByText('Admin')).toBeInTheDocument();
  });

  it('should not show Admin button for non-administrators', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: { userId: 1, email: 'user@example.com', tenantId: 1, isSystemAdministrator: false },
      loading: false,
      error: null,
      refetch: vi.fn(),
      logout: mockLogout,
    });

    renderWithRouter(<UserButton onClick={mockOnClick} />);
    expect(screen.queryByText('Admin')).not.toBeInTheDocument();
  });

  it('should call logout on Sign Out click', async () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: { userId: 1, email: 'test@example.com', tenantId: 1, isSystemAdministrator: false },
      loading: false,
      error: null,
      refetch: vi.fn(),
      logout: mockLogout,
    });

    renderWithRouter(<UserButton onClick={mockOnClick} />);
    
    const signOutButton = screen.getByText('Sign Out');
    await fireEvent.click(signOutButton);

    expect(mockLogout).toHaveBeenCalled();
    expect(mockLocation.href).toBe('/');
  });

  it('should navigate to /admin when Admin button clicked', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: { userId: 1, email: 'admin@example.com', tenantId: 1, isSystemAdministrator: true },
      loading: false,
      error: null,
      refetch: vi.fn(),
      logout: mockLogout,
    });

    renderWithRouter(<UserButton onClick={mockOnClick} />);
    
    const adminButton = screen.getByText('Admin');
    fireEvent.click(adminButton);

    expect(mockNavigate).toHaveBeenCalledWith('/admin');
  });
});
