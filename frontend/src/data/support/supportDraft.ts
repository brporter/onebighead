import type { CreateSupportRequest } from '../../api/support';
import { EMAIL_MAX_LENGTH, isValidEmail } from '../../utils/email';

export interface SupportDraft { subject: string; description: string; email: string }
export const SUPPORT_LIMITS = { subject: 200, description: 4000, email: EMAIL_MAX_LENGTH } as const;

/** Validate the same payload for native form submission and other consumers. */
export function prepareSupportRequest(draft: SupportDraft, authenticated: boolean): CreateSupportRequest {
  const subject = draft.subject.trim();
  const description = draft.description.trim();
  if (!subject) throw new Error('Enter a subject for your request.');
  if (subject.length > SUPPORT_LIMITS.subject) throw new Error('Keep the subject to 200 characters or fewer.');
  if (!description) throw new Error('Describe how we can help.');
  if (description.length > SUPPORT_LIMITS.description) throw new Error('Keep the description to 4,000 characters or fewer.');
  if (authenticated) return { subject, description };
  const email = draft.email.trim();
  if (!isValidEmail(email))
    throw new Error('Enter a valid email address where we can reply.');
  return { subject, description, email };
}
