import { useId, useState } from 'react';
import type { WorkspaceInvitation } from '../../data/invitations/types';
import { WorkspaceRole } from '../../utils/types';

export function PendingInvitations({ invitations, disabled, onRenew, onCancel }: {
  invitations: WorkspaceInvitation[]; disabled: boolean;
  onRenew: (invitation: WorkspaceInvitation) => void; onCancel: (id: string) => void;
}) {
  const id = useId();
  const [viewedAt] = useState(Date.now);
  return <section aria-labelledby={id}>
    <h3 className="team-panel__title" id={id}>Pending invitations <span className="team-panel__count">{invitations.length}</span></h3>
    {invitations.length === 0 ? <p>No pending invitations.</p> : <ul className="team-panel__members">
      {invitations.map(invitation => <li className="team-panel__member team-panel__member--pending" key={invitation.invitationId}>
        <div className="team-panel__memberInfo">
          <h4 className="team-panel__email">{invitation.email}</h4>
          <p className="team-panel__hint">{invitation.role === WorkspaceRole.WorkspaceAdmin ? 'Admin' : 'Member'} · {new Date(invitation.expiresAt).getTime() <= viewedAt
            ? 'Expired — create a new link' : `Expires ${new Date(invitation.expiresAt).toLocaleString()}`}</p>
        </div>
        <div className="team-panel__memberActions">
          <button type="button" className="team-panel__button" disabled={disabled} onClick={() => onRenew(invitation)} aria-label={`Create new link for ${invitation.email}`}>Create new link</button>
          <button type="button" className="team-panel__button team-panel__button--danger" disabled={disabled}
            onClick={() => onCancel(invitation.invitationId)} aria-label={`Cancel invitation for ${invitation.email}`}>Cancel invitation</button>
        </div>
      </li>)}
    </ul>}
  </section>;
}
