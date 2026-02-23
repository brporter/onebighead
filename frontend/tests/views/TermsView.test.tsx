import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import TermsView from '../../src/views/TermsView';
import * as UserContext from '../../src/contexts/useUser';

// Mock the UserContext
vi.mock('../../src/contexts/useUser', () => ({
  useUser: vi.fn(),
}));

// Mock TermsAcceptance component
vi.mock('../../src/components/common/TermsAcceptance', () => ({
  TermsAcceptance: ({ onAccepted, showSkip, onSkip }: { onAccepted: () => void; showSkip?: boolean; onSkip?: () => void }) => (
    <div data-testid="terms-acceptance">
      <button onClick={onAccepted}>Accept Terms</button>
      {showSkip && onSkip && <button onClick={onSkip}>Skip/Sign Out</button>}
    </div>
  ),
}));

// Mock window.location
const mockLocation = { href: '' };
Object.defineProperty(window, 'location', {
  value: mockLocation,
  writable: true,
});

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

function renderTermsView() {
  return render(
    <MemoryRouter initialEntries={['/terms']}>
      <Routes>
        <Route path="/terms" element={<TermsView />} />
        <Route path="/collections" element={<div>Collections Page</div>} />
      </Routes>
    </MemoryRouter>
  );
}

describe('TermsView', () => {
  const mockRefetch = vi.fn().mockResolvedValue(undefined);
  const mockLogout = vi.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    vi.clearAllMocks();
    mockLocation.href = '';

    vi.mocked(UserContext.useUser).mockReturnValue({
      user: null,
      loading: false,
      error: null,
      refetch: mockRefetch,
      logout: mockLogout,
    });
  });

  it('should render TermsAcceptance component', () => {
    renderTermsView();

    expect(screen.getByTestId('terms-acceptance')).toBeInTheDocument();
    expect(screen.getByText('Accept Terms')).toBeInTheDocument();
    expect(screen.getByText('Skip/Sign Out')).toBeInTheDocument();
  });

  it('should render header with logo', () => {
    renderTermsView();

    expect(screen.getByText('OneBigHead')).toBeInTheDocument();
  });

  it('should navigate to collections after accepting terms', async () => {
    const user = userEvent.setup();
    renderTermsView();

    await user.click(screen.getByText('Accept Terms'));

    expect(mockRefetch).toHaveBeenCalled();
    expect(mockNavigate).toHaveBeenCalledWith('/collections', { replace: true });
  });

  it('should logout and redirect to home on skip', async () => {
    const user = userEvent.setup();
    renderTermsView();

    await user.click(screen.getByText('Skip/Sign Out'));

    expect(mockLogout).toHaveBeenCalled();
    expect(mockLocation.href).toBe('/');
  });

  describe('snapshots', () => {
    it('should match snapshot', () => {
      const { container } = renderTermsView();
      expect(container).toMatchSnapshot();
    });
  });
});
