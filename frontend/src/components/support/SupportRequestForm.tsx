import { useId, type Dispatch, type SetStateAction } from 'react';
import { SUPPORT_LIMITS, type SupportDraft } from '../../data/support/supportDraft';
import { EMAIL_PATTERN } from '../../utils/email';
import '../../styles/components/SupportModal.css';

interface SupportRequestFormProps {
  draft: SupportDraft;
  setDraft: Dispatch<SetStateAction<SupportDraft>>;
  authenticated: boolean;
  pending: boolean;
  error: string | null;
  onSubmit: () => void | Promise<void>;
  onCancel: () => void;
}

export function SupportRequestForm({ draft, setDraft, authenticated, pending, error, onSubmit, onCancel }: SupportRequestFormProps) {
  const id = useId();
  return <form className="support-modal__form" aria-label="Support request" aria-busy={pending}
    onSubmit={event => { event.preventDefault(); void onSubmit(); }}>
    <div className="support-modal__scroll">
      {error && <p className="support-modal__error" role="alert">{error}</p>}
      <fieldset className="support-modal__fields" disabled={pending}>
        <legend className="support-modal__legend">Request details</legend>
        {!authenticated && <div className="support-modal__field">
          <label className="support-modal__label" htmlFor={`${id}-email`}>Email <span aria-hidden="true">*</span></label>
          <input type="email" id={`${id}-email`} className="support-modal__input" value={draft.email} autoComplete="email"
            pattern={EMAIL_PATTERN} maxLength={SUPPORT_LIMITS.email} required aria-describedby={`${id}-email-hint`}
            onChange={event => setDraft(previous => ({ ...previous, email: event.target.value }))} placeholder="your@email.com" />
          <p className="support-modal__hint" id={`${id}-email-hint`}>We'll send our reply to this address.</p>
        </div>}
        <div className="support-modal__field">
          <label className="support-modal__label" htmlFor={`${id}-subject`}>Subject <span aria-hidden="true">*</span></label>
          <input type="text" id={`${id}-subject`} className="support-modal__input" value={draft.subject} maxLength={SUPPORT_LIMITS.subject} required
            onChange={event => setDraft(previous => ({ ...previous, subject: event.target.value }))} placeholder="Brief summary of your issue" />
        </div>
        <div className="support-modal__field">
          <label className="support-modal__label" htmlFor={`${id}-description`}>Description <span aria-hidden="true">*</span></label>
          <textarea id={`${id}-description`} className="support-modal__textarea" value={draft.description} maxLength={SUPPORT_LIMITS.description}
            required aria-describedby={`${id}-description-hint`} rows={5}
            onChange={event => setDraft(previous => ({ ...previous, description: event.target.value }))} placeholder="Please describe your issue in detail..." />
          <p className="support-modal__hint" id={`${id}-description-hint`}>Tell us what happened and what you expected. Up to 4,000 characters.</p>
        </div>
      </fieldset>
    </div>
    <footer className="support-modal__actions">
      <button type="button" className="support-modal__button support-modal__button--secondary" onClick={onCancel} disabled={pending}>Cancel</button>
      <button type="submit" className="support-modal__button support-modal__button--primary" disabled={pending}>
        {pending ? 'Submitting...' : 'Submit Request'}
      </button>
    </footer>
  </form>;
}
