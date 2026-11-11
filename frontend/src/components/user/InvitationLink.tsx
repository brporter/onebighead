import { useId, useState } from 'react';
import type { CreatedInvitation } from '../../data/invitations/types';
import { useAsyncAction } from '../../utils/useAsyncAction';

export function InvitationLink({ created }: { created: CreatedInvitation }) {
  const id = useId();
  const action = useAsyncAction();
  const [copied, setCopied] = useState(false);
  const link = `${window.location.origin}/join/${created.invitation.invitationId}#${created.token}`;
  return <section className="team-panel__link" aria-labelledby={`${id}-title`}>
    <h3 id={`${id}-title`} className="team-panel__title">Share the private invitation</h3>
    <p>Anyone with this link can join the workspace. Send it only to {created.invitation.email}. It expires {new Date(created.invitation.expiresAt).toLocaleString()}.</p>
    <p>Copy this link now. You can create a new one later if needed.</p>
    <label htmlFor={id}>Invitation link</label>
    <input id={id} type="text" className="team-panel__input" value={link} readOnly onFocus={event => event.target.select()} />
    <button type="button" className="team-panel__button" disabled={action.pending} onClick={() => void action.run(
      () => navigator.clipboard.writeText(link), 'Unable to copy. Select and copy the link above.', () => setCopied(true))}>Copy link</button>
    {copied && <p role="status">Link copied.</p>}
    {action.error && <p role="alert" className="team-panel__error">{action.error}</p>}
  </section>;
}
