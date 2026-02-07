import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import WelcomeView from '../../src/views/WelcomeView';

// Mock WelcomeWizard component
vi.mock('../../src/components/wizard/WelcomeWizard', () => ({
  default: ({ onComplete, onSkip }: { onComplete: (collectionId: number) => void; onSkip: () => void }) => (
    <div data-testid="welcome-wizard">
      <button onClick={() => onComplete(123)}>Complete Setup</button>
      <button onClick={onSkip}>Skip Setup</button>
    </div>
  ),
}));

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

function renderWelcomeView() {
  return render(
    <MemoryRouter initialEntries={['/welcome']}>
      <Routes>
        <Route path="/welcome" element={<WelcomeView />} />
        <Route path="/collections/:id" element={<div>Collection Page</div>} />
        <Route path="/collections" element={<div>Collections List</div>} />
      </Routes>
    </MemoryRouter>
  );
}

describe('WelcomeView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render WelcomeWizard component', () => {
    renderWelcomeView();

    expect(screen.getByTestId('welcome-wizard')).toBeInTheDocument();
  });

  it('should navigate to collection page on complete', async () => {
    const user = userEvent.setup();
    renderWelcomeView();

    await user.click(screen.getByText('Complete Setup'));

    expect(mockNavigate).toHaveBeenCalledWith('/collections/123');
  });

  it('should navigate to collections list on skip', async () => {
    const user = userEvent.setup();
    renderWelcomeView();

    await user.click(screen.getByText('Skip Setup'));

    expect(mockNavigate).toHaveBeenCalledWith('/collections');
  });

  describe('snapshots', () => {
    it('should match snapshot', () => {
      const { container } = renderWelcomeView();
      expect(container).toMatchSnapshot();
    });
  });
});
