import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import TermsAcceptance from '../src/components/common/TermsAcceptance';
import { authApi } from '../src/api';
import { deferred } from './testUtils/deferred';

vi.mock('../src/api', () => ({
  authApi: {
    acceptTerms: vi.fn(),
  },
}));

describe('TermsAcceptance', () => {
  const mockOnAccepted = vi.fn();
  const mockOnSkip = vi.fn();

  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('renders title and documents', () => {
    render(<TermsAcceptance onAccepted={mockOnAccepted} />);

    expect(screen.getByText('Terms of Service & Privacy Policy')).toBeInTheDocument();
    // Use heading role since there are multiple "Terms of Service" texts on the page
    expect(screen.getByRole('heading', { name: 'Terms of Service' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Privacy Policy' })).toBeInTheDocument();
  });

  it('renders links to terms and privacy', () => {
    render(<TermsAcceptance onAccepted={mockOnAccepted} />);

    const termsLinks = screen.getAllByText('Read Terms of Service');
    const privacyLinks = screen.getAllByText('Read Privacy Policy');

    expect(termsLinks.length).toBeGreaterThan(0);
    expect(privacyLinks.length).toBeGreaterThan(0);
  });

  it('disables submit button when checkboxes are not checked', () => {
    render(<TermsAcceptance onAccepted={mockOnAccepted} />);

    const submitButton = screen.getByRole('button', { name: /accept and continue/i });
    expect(submitButton).toBeDisabled();
  });

  it('enables submit button when both checkboxes are checked', async () => {
    const user = userEvent.setup();
    render(<TermsAcceptance onAccepted={mockOnAccepted} />);

    const checkboxes = screen.getAllByRole('checkbox');
    await user.click(checkboxes[0]); // Terms checkbox
    await user.click(checkboxes[1]); // Privacy checkbox

    const submitButton = screen.getByRole('button', { name: /accept and continue/i });
    expect(submitButton).not.toBeDisabled();
  });

  it('calls acceptTerms API and onAccepted when submitted', async () => {
    const user = userEvent.setup();
    (authApi.acceptTerms as ReturnType<typeof vi.fn>).mockResolvedValue({
      hasAcceptedTerms: true,
      acceptedTermsAt: new Date().toISOString(),
    });

    render(<TermsAcceptance onAccepted={mockOnAccepted} />);

    const checkboxes = screen.getAllByRole('checkbox');
    await user.click(checkboxes[0]);
    await user.click(checkboxes[1]);

    const submitButton = screen.getByRole('button', { name: /accept and continue/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(authApi.acceptTerms).toHaveBeenCalled();
      expect(mockOnAccepted).toHaveBeenCalled();
    });
  });

  it('shows loading state while submitting', async () => {
    const user = userEvent.setup();
    let resolveAccept: (value?: unknown) => void;
    (authApi.acceptTerms as ReturnType<typeof vi.fn>).mockImplementation(
      () => new Promise((resolve) => { resolveAccept = resolve; })
    );

    render(<TermsAcceptance onAccepted={mockOnAccepted} />);

    const checkboxes = screen.getAllByRole('checkbox');
    await user.click(checkboxes[0]);
    await user.click(checkboxes[1]);

    const submitButton = screen.getByRole('button', { name: /accept and continue/i });
    await user.click(submitButton);

    expect(screen.getByRole('button', { name: /accepting/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /accepting/i })).toBeDisabled();

    await act(async () => resolveAccept!());
  });

  it('displays error when API call fails', async () => {
    const user = userEvent.setup();
    (authApi.acceptTerms as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Network error'));

    render(<TermsAcceptance onAccepted={mockOnAccepted} />);

    const checkboxes = screen.getAllByRole('checkbox');
    await user.click(checkboxes[0]);
    await user.click(checkboxes[1]);

    const submitButton = screen.getByRole('button', { name: /accept and continue/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText('Network error')).toBeInTheDocument();
    });
  });

  it('does not call onAccepted when API fails', async () => {
    const user = userEvent.setup();
    (authApi.acceptTerms as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Network error'));

    render(<TermsAcceptance onAccepted={mockOnAccepted} />);

    const checkboxes = screen.getAllByRole('checkbox');
    await user.click(checkboxes[0]);
    await user.click(checkboxes[1]);

    const submitButton = screen.getByRole('button', { name: /accept and continue/i });
    await user.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText('Network error')).toBeInTheDocument();
    });

    expect(mockOnAccepted).not.toHaveBeenCalled();
  });

  describe('with skip button', () => {
    it('omits sign-out when no callback is supplied', () => {
      render(<TermsAcceptance onAccepted={mockOnAccepted} showSkip />);
      expect(screen.queryByRole('button', { name: /sign out/i })).not.toBeInTheDocument();
    });
    it('renders skip button when showSkip is true', () => {
      render(
        <TermsAcceptance
          onAccepted={mockOnAccepted}
          showSkip={true}
          onSkip={mockOnSkip}
        />
      );

      expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument();
    });

    it('does not render skip button when showSkip is false', () => {
      render(<TermsAcceptance onAccepted={mockOnAccepted} showSkip={false} />);

      expect(screen.queryByRole('button', { name: /sign out/i })).not.toBeInTheDocument();
    });

    it('calls onSkip when skip button is clicked', async () => {
      const user = userEvent.setup();
      render(
        <TermsAcceptance
          onAccepted={mockOnAccepted}
          showSkip={true}
          onSkip={mockOnSkip}
        />
      );

      await user.click(screen.getByRole('button', { name: /sign out/i }));

      expect(mockOnSkip).toHaveBeenCalled();
    });
  });

  it('reports sign-out failure and locks all actions during a retry', async () => {
    const user = userEvent.setup();
    const retry = deferred<void>();
    const skip = vi.fn().mockRejectedValueOnce(new Error('Unable to reach server')).mockReturnValueOnce(retry.promise);
    render(<TermsAcceptance onAccepted={mockOnAccepted} showSkip onSkip={skip} />);
    await user.click(screen.getByRole('button', { name: 'Sign Out' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to reach server');
    for (const checkbox of screen.getAllByRole('checkbox')) await user.click(checkbox);
    await user.click(screen.getByRole('button', { name: 'Sign Out' }));
    expect(screen.getByRole('button', { name: 'Signing out…' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Accept and Continue' })).toBeDisabled();
    for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).toBeDisabled();
    await act(async () => retry.resolve());
    expect(screen.getByRole('button', { name: 'Sign Out' })).toBeEnabled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('awaits the acceptance continuation and shows its failure without an unhandled rejection', async () => {
    const user = userEvent.setup();
    const completion = deferred<void>();
    vi.mocked(authApi.acceptTerms).mockResolvedValue({ hasAcceptedTerms: true, acceptedTermsAt: '2026-11-10' });
    render(<TermsAcceptance onAccepted={() => completion.promise} showSkip onSkip={mockOnSkip} />);
    for (const checkbox of screen.getAllByRole('checkbox')) await user.click(checkbox);
    await user.click(screen.getByRole('button', { name: 'Accept and Continue' }));
    expect(screen.getByRole('button', { name: 'Accepting...' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Sign Out' })).toBeDisabled();
    await act(async () => completion.reject(new Error('Session refresh failed')));
    expect(screen.getByRole('alert')).toHaveTextContent('Session refresh failed');
    expect(screen.getByRole('button', { name: 'Accept and Continue' })).toBeEnabled();
  });

  it('retries only the continuation after terms acceptance has been confirmed', async () => {
    const user = userEvent.setup();
    vi.mocked(authApi.acceptTerms).mockResolvedValue({ hasAcceptedTerms: true, acceptedTermsAt: '2026-11-10' });
    const accepted = vi.fn().mockRejectedValueOnce(new Error('Refresh failed')).mockResolvedValue(undefined);
    render(<TermsAcceptance onAccepted={accepted} />);
    for (const checkbox of screen.getAllByRole('checkbox')) await user.click(checkbox);
    await user.click(screen.getByRole('button', { name: 'Accept and Continue' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Refresh failed');
    await user.click(screen.getByRole('button', { name: 'Accept and Continue' }));
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
    expect(authApi.acceptTerms).toHaveBeenCalledOnce();
    expect(accepted).toHaveBeenCalledTimes(2);
  });

  describe('checkbox interactions', () => {
    it('can check and uncheck terms checkbox', async () => {
      const user = userEvent.setup();
      render(<TermsAcceptance onAccepted={mockOnAccepted} />);

      const termsCheckbox = screen.getAllByRole('checkbox')[0];
      expect(termsCheckbox).not.toBeChecked();

      await user.click(termsCheckbox);
      expect(termsCheckbox).toBeChecked();

      await user.click(termsCheckbox);
      expect(termsCheckbox).not.toBeChecked();
    });

    it('requires both checkboxes to be checked', async () => {
      const user = userEvent.setup();
      render(<TermsAcceptance onAccepted={mockOnAccepted} />);

      const checkboxes = screen.getAllByRole('checkbox');
      const submitButton = screen.getByRole('button', { name: /accept and continue/i });

      // Only terms checked
      await user.click(checkboxes[0]);
      expect(submitButton).toBeDisabled();

      // Uncheck terms, check privacy
      await user.click(checkboxes[0]);
      await user.click(checkboxes[1]);
      expect(submitButton).toBeDisabled();

      // Both checked
      await user.click(checkboxes[0]);
      expect(submitButton).not.toBeDisabled();
    });
  });
});
