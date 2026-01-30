import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route, Navigate } from 'react-router-dom';
import RequireAuth from '../src/components/common/RequireAuth';
import * as UserContext from '../src/contexts/UserContext';
import type { CurrentUser } from '../src/utils/types';

vi.mock('../src/contexts/UserContext', () => ({
  useUser: vi.fn(),
}));

// Mock window.location
const mockLocation = {
  href: '',
};
Object.defineProperty(window, 'location', {
  value: mockLocation,
  writable: true,
});

function renderWithRouter(children: React.ReactNode, initialRoute = '/collections') {
  return render(
    <MemoryRouter initialEntries={[initialRoute]}>
      <Routes>
        <Route path="*" element={children} />
        <Route path="/welcome" element={<div>Welcome Page</div>} />
      </Routes>
    </MemoryRouter>
  );
}

const createUser = (overrides: Partial<CurrentUser> = {}): CurrentUser => ({
  userId: 1,
  email: 'test@example.com',
  tenantId: 1,
  tenantName: 'Test Tenant',
  hasCompletedWelcome: true,
  isSystemAdministrator: false,
  ...overrides,
});

describe('RequireAuth', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLocation.href = '';
  });

  it('should show loading state while checking auth', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: null,
      loading: true,
      error: null,
      refetch: vi.fn(),
      logout: vi.fn(),
    });

    renderWithRouter(
      <RequireAuth>
        <div>Protected Content</div>
      </RequireAuth>
    );

    expect(screen.getByText('Loading...')).toBeInTheDocument();
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });

  it('should render children when user is authenticated and has completed welcome', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: createUser({ hasCompletedWelcome: true }),
      loading: false,
      error: null,
      refetch: vi.fn(),
      logout: vi.fn(),
    });

    renderWithRouter(
      <RequireAuth>
        <div>Protected Content</div>
      </RequireAuth>
    );

    expect(screen.getByText('Protected Content')).toBeInTheDocument();
  });

  it('should redirect to signin when user is not authenticated', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: null,
      loading: false,
      error: null,
      refetch: vi.fn(),
      logout: vi.fn(),
    });

    renderWithRouter(
      <RequireAuth>
        <div>Protected Content</div>
      </RequireAuth>,
      '/collections/1'
    );

    expect(mockLocation.href).toBe('/signin?returnUrl=%2Fcollections%2F1');
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });

  it('should include search params in return URL', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: null,
      loading: false,
      error: null,
      refetch: vi.fn(),
      logout: vi.fn(),
    });

    renderWithRouter(
      <RequireAuth>
        <div>Protected Content</div>
      </RequireAuth>,
      '/collections/1/items/new?categoryId=5'
    );

    expect(mockLocation.href).toBe('/signin?returnUrl=%2Fcollections%2F1%2Fitems%2Fnew%3FcategoryId%3D5');
  });

  describe('welcome redirect', () => {
    it('should redirect to /welcome when hasCompletedWelcome is false', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: createUser({ hasCompletedWelcome: false }),
        loading: false,
        error: null,
        refetch: vi.fn(),
        logout: vi.fn(),
      });

      renderWithRouter(
        <RequireAuth>
          <div>Protected Content</div>
        </RequireAuth>,
        '/collections'
      );

      expect(screen.getByText('Welcome Page')).toBeInTheDocument();
      expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
    });

    it('should not redirect to /welcome when skipWelcomeCheck is true', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: createUser({ hasCompletedWelcome: false }),
        loading: false,
        error: null,
        refetch: vi.fn(),
        logout: vi.fn(),
      });

      // Render without routing to test the component directly
      render(
        <MemoryRouter initialEntries={['/welcome']}>
          <RequireAuth skipWelcomeCheck>
            <div>Welcome Wizard Content</div>
          </RequireAuth>
        </MemoryRouter>
      );

      expect(screen.getByText('Welcome Wizard Content')).toBeInTheDocument();
    });

    it('should allow access when hasCompletedWelcome is true', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: createUser({ hasCompletedWelcome: true }),
        loading: false,
        error: null,
        refetch: vi.fn(),
        logout: vi.fn(),
      });

      renderWithRouter(
        <RequireAuth>
          <div>Protected Content</div>
        </RequireAuth>,
        '/collections'
      );

      expect(screen.getByText('Protected Content')).toBeInTheDocument();
    });
  });

  describe('snapshots', () => {
    it('should match snapshot for loading state', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: null,
        loading: true,
        error: null,
        refetch: vi.fn(),
        logout: vi.fn(),
      });

      const { container } = render(
        <MemoryRouter>
          <RequireAuth>
            <div>Protected Content</div>
          </RequireAuth>
        </MemoryRouter>
      );
      expect(container).toMatchSnapshot();
    });

    it('should match snapshot for authenticated state', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: createUser({ hasCompletedWelcome: true }),
        loading: false,
        error: null,
        refetch: vi.fn(),
        logout: vi.fn(),
      });

      const { container } = render(
        <MemoryRouter>
          <RequireAuth>
            <div>Protected Content</div>
          </RequireAuth>
        </MemoryRouter>
      );
      expect(container).toMatchSnapshot();
    });
  });
});
