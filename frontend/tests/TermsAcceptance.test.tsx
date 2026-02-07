import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import TermsAcceptance from '../src/components/common/TermsAcceptance';
import { authApi } from '../src/api';

vi.mock('../src/api', () => ({
  authApi: {
    acceptTerms: vi.fn(),
  },
}));

describe('TermsAcceptance', () => {
  const mockOnAccepted = vi.fn();
  const mockOnSkip = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
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

    resolveAccept!();
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
