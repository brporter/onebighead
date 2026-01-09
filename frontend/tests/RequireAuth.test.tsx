import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import RequireAuth from '../src/RequireAuth';
import * as UserContext from '../src/UserContext';

vi.mock('../src/UserContext', () => ({
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
      {children}
    </MemoryRouter>
  );
}

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
    });

    renderWithRouter(
      <RequireAuth>
        <div>Protected Content</div>
      </RequireAuth>
    );

    expect(screen.getByText('Loading...')).toBeInTheDocument();
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });

  it('should render children when user is authenticated', () => {
    vi.mocked(UserContext.useUser).mockReturnValue({
      user: { userId: 1, email: 'test@example.com', tenantId: 1 },
      loading: false,
      error: null,
      refetch: vi.fn(),
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
    });

    renderWithRouter(
      <RequireAuth>
        <div>Protected Content</div>
      </RequireAuth>,
      '/collections/1/items/new?categoryId=5'
    );

    expect(mockLocation.href).toBe('/signin?returnUrl=%2Fcollections%2F1%2Fitems%2Fnew%3FcategoryId%3D5');
  });
});
