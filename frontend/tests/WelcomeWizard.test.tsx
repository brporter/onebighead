import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import WelcomeWizard from '../src/components/wizard/WelcomeWizard';
import * as UserContext from '../src/contexts/UserContext';
import * as DataContext from '../src/contexts/DataContext';
import * as authApi from '../src/api/auth';
import type { CurrentUser, CollectionTheme } from '../src/utils/types';

vi.mock('../src/contexts/UserContext', () => ({
  useUser: vi.fn(),
}));

vi.mock('../src/contexts/DataContext', () => ({
  useData: vi.fn(),
}));

vi.mock('../src/api/auth', () => ({
  authApi: {
    completeWelcome: vi.fn(),
  },
}));

const createUser = (overrides: Partial<CurrentUser> = {}): CurrentUser => ({
  userId: 1,
  email: 'test@example.com',
  workspaceId: 1,
  workspaceName: 'Test Workspace',
  hasCompletedWelcome: false,
  hasAcceptedTerms: true, // Default to true so tests start at welcome step
  isSystemAdministrator: false,
  workspaceRole: 'Normal' as const,
  isWorkspaceAdmin: false,
  ...overrides,
});

const mockThemes: CollectionTheme[] = [
  {
    themeId: 1,
    name: 'General',
    description: 'A general-purpose theme',
    templates: [],
    categories: [],
  },
  {
    themeId: 2,
    name: 'Books',
    description: 'For book collections',
    templates: [],
    categories: [],
  },
];

describe('WelcomeWizard', () => {
  const mockOnComplete = vi.fn();
  const mockOnSkip = vi.fn();
  const mockRefetch = vi.fn();
  const mockLoadThemes = vi.fn();
  const mockSetupCollection = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(UserContext.useUser).mockReturnValue({
      user: createUser(),
      loading: false,
      error: null,
      refetch: mockRefetch,
      logout: vi.fn(),
    });

    vi.mocked(DataContext.useData).mockReturnValue({
      themes: mockThemes,
      themesLoading: false,
      loadThemes: mockLoadThemes,
      setupCollection: mockSetupCollection,
      // Include other required DataContext properties as needed
    } as ReturnType<typeof DataContext.useData>);
  });

  it('should render welcome step initially', () => {
    render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);

    expect(screen.getByText('Welcome to OneBigHead!')).toBeInTheDocument();
    expect(screen.getByLabelText(/Organization \/ Workspace Name/)).toBeInTheDocument();
    expect(screen.getByLabelText(/First Collection Name/)).toBeInTheDocument();
  });

  it('should pre-fill workspace name with user email', () => {
    render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);

    const workspaceNameInput = screen.getByLabelText(/Organization \/ Workspace Name/) as HTMLInputElement;
    expect(workspaceNameInput.value).toBe('test@example.com');
  });

  it('should allow entering workspace name and collection name', async () => {
    const user = userEvent.setup();
    render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);

    const workspaceNameInput = screen.getByLabelText(/Organization \/ Workspace Name/) as HTMLInputElement;
    const collectionNameInput = screen.getByLabelText(/First Collection Name/) as HTMLInputElement;

    // Triple-click to select all, then type to replace
    await user.tripleClick(workspaceNameInput);
    await user.keyboard('My Organization');
    await user.type(collectionNameInput, 'My Books');

    expect(workspaceNameInput.value).toBe('My Organization');
    expect(collectionNameInput.value).toBe('My Books');
  });

  it('should disable Next button when required fields are empty', () => {
    render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);

    // Collection name is empty by default
    const nextButton = screen.getByRole('button', { name: 'Next' });
    expect(nextButton).toBeDisabled();
  });

  it('should enable Next button when required fields are filled', async () => {
    const user = userEvent.setup();
    render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);

    const collectionNameInput = screen.getByLabelText(/First Collection Name/);
    await user.type(collectionNameInput, 'My Collection');

    const nextButton = screen.getByRole('button', { name: 'Next' });
    expect(nextButton).not.toBeDisabled();
  });

  it('should proceed to theme step when Next is clicked', async () => {
    const user = userEvent.setup();
    render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);

    const collectionNameInput = screen.getByLabelText(/First Collection Name/);
    await user.type(collectionNameInput, 'My Collection');

    const nextButton = screen.getByRole('button', { name: 'Next' });
    await user.click(nextButton);

    expect(screen.getByText(/Choose a theme to get started/)).toBeInTheDocument();
  });

  it('should call skip handler when Skip button is clicked', async () => {
    const user = userEvent.setup();
    vi.mocked(authApi.authApi.completeWelcome).mockResolvedValue({
      workspaceId: 1,
      workspaceName: 'test@example.com',
      hasCompletedWelcome: true,
    });
    mockRefetch.mockResolvedValue(undefined);

    render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);

    const skipButton = screen.getByRole('button', { name: 'Skip Setup' });
    await user.click(skipButton);

    await waitFor(() => {
      expect(authApi.authApi.completeWelcome).toHaveBeenCalledWith(undefined);
      expect(mockRefetch).toHaveBeenCalled();
      expect(mockOnSkip).toHaveBeenCalled();
    });
  });

  it('should auto-select General theme', async () => {
    const user = userEvent.setup();
    render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);

    // Fill required fields and go to theme step
    const collectionNameInput = screen.getByLabelText(/First Collection Name/);
    await user.type(collectionNameInput, 'My Collection');
    await user.click(screen.getByRole('button', { name: 'Next' }));

    // The General theme should be auto-selected
    // We can verify by going to preview - it should work without manually selecting
    await user.click(screen.getByRole('button', { name: 'Next' }));

    expect(screen.getByText('Setup Summary')).toBeInTheDocument();
    expect(screen.getByText('General')).toBeInTheDocument();
  });

  it('should complete setup and create collection on submit', async () => {
    const user = userEvent.setup();
    vi.mocked(authApi.authApi.completeWelcome).mockResolvedValue({
      workspaceId: 1,
      workspaceName: 'My Org',
      hasCompletedWelcome: true,
    });
    mockRefetch.mockResolvedValue(undefined);
    mockSetupCollection.mockResolvedValue({ collectionId: 42 });

    render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);

    // Step 1: Welcome
    const workspaceNameInput = screen.getByLabelText(/Organization \/ Workspace Name/);
    const collectionNameInput = screen.getByLabelText(/First Collection Name/);
    // Use triple-click to select all, then type to replace
    await user.tripleClick(workspaceNameInput);
    await user.keyboard('My Org');
    await user.type(collectionNameInput, 'My Collection');
    await user.click(screen.getByRole('button', { name: 'Next' }));

    // Step 2: Theme (General is auto-selected)
    await user.click(screen.getByRole('button', { name: 'Next' }));

    // Step 3: Preview - submit
    await user.click(screen.getByRole('button', { name: 'Get Started' }));

    await waitFor(() => {
      expect(authApi.authApi.completeWelcome).toHaveBeenCalledWith('My Org');
      expect(mockSetupCollection).toHaveBeenCalledWith({
        name: 'My Collection',
        description: '',
        themeId: 1, // General theme
      });
      expect(mockOnComplete).toHaveBeenCalledWith(42);
    });
  });

  it('should load themes on mount', () => {
    render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);

    expect(mockLoadThemes).toHaveBeenCalled();
  });

  it('should show loading state when themes are loading', async () => {
    const user = userEvent.setup();
    vi.mocked(DataContext.useData).mockReturnValue({
      themes: [],
      themesLoading: true,
      loadThemes: mockLoadThemes,
      setupCollection: mockSetupCollection,
    } as ReturnType<typeof DataContext.useData>);

    render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);

    // Go to theme step
    const collectionNameInput = screen.getByLabelText(/First Collection Name/);
    await user.type(collectionNameInput, 'My Collection');
    await user.click(screen.getByRole('button', { name: 'Next' }));

    expect(screen.getByText('Loading themes...')).toBeInTheDocument();
  });

  describe('terms acceptance step', () => {
    it('should show terms step first when user has not accepted terms', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: createUser({ hasAcceptedTerms: false }),
        loading: false,
        error: null,
        refetch: mockRefetch,
        logout: vi.fn(),
      });

      render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);

      expect(screen.getByText('Terms of Service & Privacy Policy')).toBeInTheDocument();
      // Skip button should not be visible on terms step
      expect(screen.queryByRole('button', { name: 'Skip Setup' })).not.toBeInTheDocument();
    });

    it('should skip terms step when user has already accepted terms', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: createUser({ hasAcceptedTerms: true }),
        loading: false,
        error: null,
        refetch: mockRefetch,
        logout: vi.fn(),
      });

      render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);

      expect(screen.getByText('Welcome to OneBigHead!')).toBeInTheDocument();
      expect(screen.queryByText('Terms of Service & Privacy Policy')).not.toBeInTheDocument();
    });
  });

  describe('snapshots', () => {
    it('should match snapshot for initial welcome step', () => {
      const { container } = render(<WelcomeWizard onComplete={mockOnComplete} onSkip={mockOnSkip} />);
      expect(container).toMatchSnapshot();
    });
  });
});
