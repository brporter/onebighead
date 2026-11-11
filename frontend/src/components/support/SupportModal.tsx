import { useEffect, useRef } from 'react';
import { ModalDialog } from '../common/ModalDialog';
import { createSupportRequest } from '../../api';
import type { SupportSubmissionPort } from '../../data/support/ports';
import { useSupportSubmission } from '../../data/support/useSupportSubmission';
import { SupportRequestForm } from './SupportRequestForm';
import '../../styles/components/SupportModal.css';

interface SupportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
  userEmail?: string | null;
}
const gateway: SupportSubmissionPort = { create: createSupportRequest };

export function SupportModal({ isOpen, ...props }: SupportModalProps) {
  return isOpen ? <SupportComposer key={props.userEmail ?? 'anonymous'} {...props} /> : null;
}

function SupportComposer({ onClose, onSuccess, userEmail }: Omit<SupportModalProps, 'isOpen'>) {
  const form = useSupportSubmission(Boolean(userEmail), gateway);
  const notified = useRef(false);
  useEffect(() => {
    if (!form.submitted || notified.current) return;
    notified.current = true;
    onSuccess?.();
  }, [form.submitted, onSuccess]);

  const close = () => {
    if (form.pending) return;
    if (form.dirty && !window.confirm('Discard your unsent support request?')) return;
    onClose();
  };
  const title = form.submitted ? 'Request Submitted' : 'Contact Support';

  return <ModalDialog label={title} onClose={close}>
    <div className="support-modal__container">
      <header className="support-modal__header">
        <h2 className="support-modal__title">{title}</h2>
        <button type="button" className="support-modal__close" onClick={close} disabled={form.pending} aria-label="Close">×</button>
      </header>
      <div className="support-modal__body">
        {form.submitted ? <div className="support-modal__success">
          <div role="status">
            <div className="support-modal__success-icon" aria-hidden="true">✓</div>
            <h3 className="support-modal__success-title">Thank you for reaching out!</h3>
            <p className="support-modal__success-message">{userEmail
              ? "We've received your support request. You can track its status and any replies in your Settings under Support Requests."
              : "We've received your support request. We'll respond to the email address you provided."}</p>
          </div>
          <button type="button" className="support-modal__button support-modal__button--primary" onClick={close}>Close</button>
        </div> : <SupportRequestForm draft={form.draft} setDraft={form.setDraft} authenticated={Boolean(userEmail)}
          pending={form.pending} error={form.error} onSubmit={form.submit} onCancel={close} />}
      </div>
    </div>
  </ModalDialog>;
}
