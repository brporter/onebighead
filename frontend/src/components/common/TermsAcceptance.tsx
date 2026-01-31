import { useState } from 'react';
import { authApi } from '../../api';
import '../../styles/TermsAcceptance.css';

interface TermsAcceptanceProps {
  onAccepted: () => void;
  showSkip?: boolean;
  onSkip?: () => void;
}

export function TermsAcceptance({ onAccepted, showSkip = false, onSkip }: TermsAcceptanceProps) {
  const [termsChecked, setTermsChecked] = useState(false);
  const [privacyChecked, setPrivacyChecked] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canContinue = termsChecked && privacyChecked;

  const handleAccept = async () => {
    if (!canContinue) return;

    setIsSubmitting(true);
    setError(null);

    try {
      await authApi.acceptTerms();
      onAccepted();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to accept terms');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="terms-acceptance">
      <div className="terms-acceptance__header">
        <h2 className="terms-acceptance__title">Terms of Service & Privacy Policy</h2>
        <p className="terms-acceptance__subtitle">
          Before you continue, please review and accept our terms.
        </p>
      </div>

      <div className="terms-acceptance__documents">
        <div className="terms-acceptance__document">
          <h3>Terms of Service</h3>
          <p>
            Our Terms of Service govern your use of OneBigHead and outline your rights
            and responsibilities as a user.
          </p>
          <a
            href="/terms"
            target="_blank"
            rel="noopener noreferrer"
            className="terms-acceptance__link"
          >
            Read Terms of Service
          </a>
        </div>

        <div className="terms-acceptance__document">
          <h3>Privacy Policy</h3>
          <p>
            Our Privacy Policy explains how we collect, use, and protect your personal
            information and collection data.
          </p>
          <a
            href="/privacy"
            target="_blank"
            rel="noopener noreferrer"
            className="terms-acceptance__link"
          >
            Read Privacy Policy
          </a>
        </div>
      </div>

      {error && <div className="terms-acceptance__error">{error}</div>}

      <div className="terms-acceptance__checkboxes">
        <label className="terms-acceptance__checkbox">
          <input
            type="checkbox"
            checked={termsChecked}
            onChange={(e) => setTermsChecked(e.target.checked)}
          />
          <span>
            I have read and agree to the <a href="/terms" target="_blank" rel="noopener noreferrer">Terms of Service</a>
          </span>
        </label>

        <label className="terms-acceptance__checkbox">
          <input
            type="checkbox"
            checked={privacyChecked}
            onChange={(e) => setPrivacyChecked(e.target.checked)}
          />
          <span>
            I have read and agree to the <a href="/privacy" target="_blank" rel="noopener noreferrer">Privacy Policy</a>
          </span>
        </label>
      </div>

      <div className="terms-acceptance__actions">
        {showSkip && onSkip && (
          <button
            type="button"
            className="terms-acceptance__button terms-acceptance__button--secondary"
            onClick={onSkip}
          >
            Sign Out
          </button>
        )}
        <button
          type="button"
          className="terms-acceptance__button terms-acceptance__button--primary"
          onClick={handleAccept}
          disabled={!canContinue || isSubmitting}
        >
          {isSubmitting ? 'Accepting...' : 'Accept and Continue'}
        </button>
      </div>
    </div>
  );
}

export default TermsAcceptance;
