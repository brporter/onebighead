import { useState } from 'react';
import { authApi } from '../../api';
import { useAsyncAction } from '../../utils/useAsyncAction';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import '../../styles/TermsAcceptance.css';

interface TermsAcceptanceProps {
  onAccepted: () => void | Promise<void>;
  showSkip?: boolean;
  onSkip?: () => void | Promise<void>;
  onStatusChange?: EditorStatusListener;
}

export function TermsAcceptance({ onAccepted, showSkip = false, onSkip, onStatusChange }: TermsAcceptanceProps) {
  const [termsChecked, setTermsChecked] = useState(false);
  const [privacyChecked, setPrivacyChecked] = useState(false);
  const action = useAsyncAction();
  const [accepting, setAccepting] = useState(false);
  const [accepted, setAccepted] = useState(false);
  useEditorStatus(!accepted && (termsChecked || privacyChecked), action.pending, onStatusChange);

  const canContinue = termsChecked && privacyChecked;

  const handleAccept = () => {
    setAccepting(true);
    void action.run(async () => {
      if (!accepted) {
        await authApi.acceptTerms();
        setAccepted(true);
      }
      await onAccepted();
    }, 'Failed to accept terms');
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

      {action.error && <div className="terms-acceptance__error" role="alert">{action.error}</div>}

      <div className="terms-acceptance__checkboxes">
        <label className="terms-acceptance__checkbox">
          <input
            type="checkbox"
            checked={termsChecked}
            disabled={action.pending}
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
            disabled={action.pending}
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
            disabled={action.pending}
            onClick={() => {
              setAccepting(false);
              void action.run(onSkip, 'Unable to sign out');
            }}
          >
            {action.pending && !accepting ? 'Signing out…' : 'Sign Out'}
          </button>
        )}
        <button
          type="button"
          className="terms-acceptance__button terms-acceptance__button--primary"
          onClick={handleAccept}
          disabled={!canContinue || action.pending}
        >
          {action.pending && accepting ? 'Accepting...' : 'Accept and Continue'}
        </button>
      </div>
    </div>
  );
}

export default TermsAcceptance;
