import React, { useState } from 'react';
import { createSupportRequest, type CreateSupportRequest } from '../../api';
import '../../styles/Support.css';

interface SupportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
  userEmail?: string | null;
}

export function SupportModal({ isOpen, onClose, onSuccess, userEmail }: SupportModalProps) {
  const [subject, setSubject] = useState('');
  const [description, setDescription] = useState('');
  const [email, setEmail] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [isSuccess, setIsSuccess] = useState(false);

  const validateEmail = (email: string): boolean => {
    if (!email) return false;
    // RFC 5322 simplified email regex
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setEmailError(null);
    setIsSubmitting(true);

    // Validate email for anonymous users
    if (!userEmail && !validateEmail(email)) {
      setEmailError('Please enter a valid email address');
      setIsSubmitting(false);
      return;
    }

    try {
      const request: CreateSupportRequest = {
        subject,
        description,
      };

      // Include email only for non-logged-in users
      if (!userEmail) {
        request.email = email;
      }

      await createSupportRequest(request);
      setIsSuccess(true);
      onSuccess?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit support request');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleClose = () => {
    setSubject('');
    setDescription('');
    setEmail('');
    setError(null);
    setEmailError(null);
    setIsSuccess(false);
    onClose();
  };

  const handleOverlayClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      handleClose();
    }
  };

  return (
    <div className="support-modal" onClick={handleOverlayClick}>
      <div className="support-modal__container">
        <div className="support-modal__header">
          <h2 className="support-modal__title">
            {isSuccess ? 'Request Submitted' : 'Contact Support'}
          </h2>
          <button
            className="support-modal__close"
            onClick={handleClose}
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="support-modal__body">
          {isSuccess ? (
            <div className="support-modal__success">
              <div className="support-modal__success-icon">✓</div>
              <h3 className="support-modal__success-title">
                Thank you for reaching out!
              </h3>
              <p className="support-modal__success-message">
                {userEmail
                  ? "We've received your support request. You can track its status and any replies in your Settings under Support Requests."
                  : "We've received your support request. We'll respond to the email address you provided."}
              </p>
              <button
                className="support-modal__button support-modal__button--primary"
                onClick={handleClose}
              >
                Close
              </button>
            </div>
          ) : (
            <form className="support-modal__form" onSubmit={handleSubmit}>
              {error && (
                <div className="support-modal__error">{error}</div>
              )}

              {!userEmail && (
                <div className="support-modal__field">
                  <label className="support-modal__label">
                    Email <span className="support-modal__required">*</span>
                  </label>
                  <input
                    type="email"
                    className={`support-modal__input${emailError ? ' support-modal__input--error' : ''}`}
                    value={email}
                    onChange={(e) => {
                      setEmail(e.target.value);
                      if (emailError) setEmailError(null);
                    }}
                    placeholder="your@email.com"
                    required
                  />
                  {emailError && (
                    <span className="support-modal__field-error">{emailError}</span>
                  )}
                </div>
              )}

              <div className="support-modal__field">
                <label className="support-modal__label">
                  Subject <span className="support-modal__required">*</span>
                </label>
                <input
                  type="text"
                  className="support-modal__input"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  placeholder="Brief summary of your issue"
                  required
                />
              </div>

              <div className="support-modal__field">
                <label className="support-modal__label">
                  Description <span className="support-modal__required">*</span>
                </label>
                <textarea
                  className="support-modal__textarea"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Please describe your issue in detail..."
                  required
                />
              </div>

              <div className="support-modal__actions">
                <button
                  type="button"
                  className="support-modal__button support-modal__button--secondary"
                  onClick={handleClose}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="support-modal__button support-modal__button--primary"
                  disabled={isSubmitting}
                >
                  {isSubmitting ? 'Submitting...' : 'Submit Request'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
