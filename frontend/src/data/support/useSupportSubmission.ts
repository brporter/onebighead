import { useState } from 'react';
import { useAsyncAction } from '../../utils/useAsyncAction';
import type { SupportSubmissionPort } from './ports';
import { prepareSupportRequest, type SupportDraft } from './supportDraft';

/** One mounted composer owns one draft and at most one successful submission. */
export function useSupportSubmission(authenticated: boolean, gateway: SupportSubmissionPort) {
  const [draft, setDraft] = useState<SupportDraft>({ subject: '', description: '', email: '' });
  const [submitted, setSubmitted] = useState(false);
  const action = useAsyncAction();
  return {
    draft, setDraft, submitted, pending: action.pending, error: action.error,
    dirty: !submitted && Object.values(draft).some(value => value.length > 0),
    submit: () => {
      if (submitted) return;
      return action.run(() => gateway.create(prepareSupportRequest(draft, authenticated)),
        'Failed to submit support request', () => setSubmitted(true));
    },
  };
}
