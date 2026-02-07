import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import SetupView from '../../src/views/SetupView';

// Mock CollectionSetupWizard component
vi.mock('../../src/components/collection/CollectionSetupWizard', () => ({
  default: ({ onComplete }: { onComplete: (collectionId: number) => void }) => (
    <div data-testid="collection-setup-wizard">
      <button onClick={() => onComplete(456)}>Complete Collection Setup</button>
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

function renderSetupView() {
  return render(
    <MemoryRouter initialEntries={['/setup']}>
      <Routes>
        <Route path="/setup" element={<SetupView />} />
        <Route path="/collections/:id" element={<div>Collection Page</div>} />
      </Routes>
    </MemoryRouter>
  );
}

describe('SetupView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render CollectionSetupWizard component', () => {
    renderSetupView();

    expect(screen.getByTestId('collection-setup-wizard')).toBeInTheDocument();
  });

  it('should navigate to collection page on complete', async () => {
    const user = userEvent.setup();
    renderSetupView();

    await user.click(screen.getByText('Complete Collection Setup'));

    expect(mockNavigate).toHaveBeenCalledWith('/collections/456');
  });

  describe('snapshots', () => {
    it('should match snapshot', () => {
      const { container } = renderSetupView();
      expect(container).toMatchSnapshot();
    });
  });
});
