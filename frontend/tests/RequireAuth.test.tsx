import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import RequireAuth from '../src/components/common/RequireAuth';
import * as UserContext from '../src/contexts/useUser';
import type { CurrentUser, WorkspaceMembership } from '../src/utils/types';
import { WorkspaceRole } from '../src/utils/types';

vi.mock('../src/contexts/useUser', () => ({
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
        <Route path="/terms" element={<div>Terms Page</div>} />
      </Routes>
    </MemoryRouter>
  );
}

const createUser = (overrides: Partial<CurrentUser> = {}): CurrentUser => {
  const activeWorkspace: WorkspaceMembership = {
    workspaceId: 1,
    workspaceName: 'Test Workspace',
    workspaceRole: WorkspaceRole.Normal,
    hasCompletedWelcome: true,
  };
  return {
    userId: 1,
    email: 'test@example.com',
    workspaceId: 1,
    workspaceName: 'Test Workspace',
    activeWorkspace,
    workspaces: [activeWorkspace],
    hasCompletedWelcome: true,
    hasAcceptedTerms: true,
    isSystemAdministrator: false,
    workspaceRole: WorkspaceRole.Normal,
    isWorkspaceAdmin: false,
    ...overrides,
  };
};

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

  it('should redirect to signin when user is not authenticated', async () => {
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

    await waitFor(() => {
      expect(mockLocation.href).toBe('/signin?returnUrl=%2Fcollections%2F1');
    });
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });

  it('should include search params in return URL', async () => {
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

    await waitFor(() => {
      expect(mockLocation.href).toBe('/signin?returnUrl=%2Fcollections%2F1%2Fitems%2Fnew%3FcategoryId%3D5');
    });
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

  describe('terms redirect', () => {
    it('should redirect to /terms when hasAcceptedTerms is false and hasCompletedWelcome is true', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: createUser({ hasAcceptedTerms: false, hasCompletedWelcome: true }),
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

      expect(screen.getByText('Terms Page')).toBeInTheDocument();
      expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
    });

    it('should not redirect to /terms for new users (hasCompletedWelcome false)', () => {
      // New users should go to welcome wizard, where terms are part of the flow
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: createUser({ hasAcceptedTerms: false, hasCompletedWelcome: false }),
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
      expect(screen.queryByText('Terms Page')).not.toBeInTheDocument();
    });

    it('should not redirect to /terms when skipTermsCheck is true', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: createUser({ hasAcceptedTerms: false, hasCompletedWelcome: true }),
        loading: false,
        error: null,
        refetch: vi.fn(),
        logout: vi.fn(),
      });

      render(
        <MemoryRouter initialEntries={['/terms']}>
          <RequireAuth skipTermsCheck>
            <div>Terms Content</div>
          </RequireAuth>
        </MemoryRouter>
      );

      expect(screen.getByText('Terms Content')).toBeInTheDocument();
    });

    it('should allow access when hasAcceptedTerms is true', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: createUser({ hasAcceptedTerms: true, hasCompletedWelcome: true }),
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
