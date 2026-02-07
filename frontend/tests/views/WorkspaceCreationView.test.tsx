import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import WorkspaceCreationView from '../../src/views/WorkspaceCreationView';

// Mock WorkspaceSetupWizard component
vi.mock('../../src/components/wizard/WorkspaceSetupWizard', () => ({
  default: ({ showTerms, isWelcome, onComplete, onCancel }: {
    showTerms: boolean;
    isWelcome: boolean;
    onComplete: () => void;
    onCancel: () => void;
  }) => (
    <div data-testid="workspace-setup-wizard">
      <span data-testid="show-terms">{showTerms.toString()}</span>
      <span data-testid="is-welcome">{isWelcome.toString()}</span>
      <button onClick={onComplete}>Complete Workspace Setup</button>
      <button onClick={onCancel}>Cancel Workspace Setup</button>
    </div>
  ),
}));

// Mock window.location
const mockLocation = { href: '' };
Object.defineProperty(window, 'location', {
  value: mockLocation,
  writable: true,
});

describe('WorkspaceCreationView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLocation.href = '';
  });

  it('should render WorkspaceSetupWizard component', () => {
    render(<WorkspaceCreationView />);

    expect(screen.getByTestId('workspace-setup-wizard')).toBeInTheDocument();
  });

  it('should pass showTerms=false to wizard', () => {
    render(<WorkspaceCreationView />);

    expect(screen.getByTestId('show-terms')).toHaveTextContent('false');
  });

  it('should pass isWelcome=false to wizard', () => {
    render(<WorkspaceCreationView />);

    expect(screen.getByTestId('is-welcome')).toHaveTextContent('false');
  });

  it('should redirect to collections on complete', async () => {
    const user = userEvent.setup();
    render(<WorkspaceCreationView />);

    await user.click(screen.getByText('Complete Workspace Setup'));

    expect(mockLocation.href).toBe('/collections');
  });

  it('should redirect to home on cancel', async () => {
    const user = userEvent.setup();
    render(<WorkspaceCreationView />);

    await user.click(screen.getByText('Cancel Workspace Setup'));

    expect(mockLocation.href).toBe('/');
  });

  describe('snapshots', () => {
    it('should match snapshot', () => {
      const { container } = render(<WorkspaceCreationView />);
      expect(container).toMatchSnapshot();
    });
  });
});
