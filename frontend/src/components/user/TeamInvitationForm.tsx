import { useId } from 'react';
import { WorkspaceRole } from '../../utils/types';
import { EMAIL_MAX_LENGTH, EMAIL_PATTERN } from '../../utils/email';
import '../../styles/components/TeamManagement.css';

interface TeamInvitationFormProps {
  email: string;
  role: WorkspaceRole;
  setEmail: (value: string) => void;
  setRole: (value: WorkspaceRole) => void;
  disabled: boolean;
  onInvite: () => void | Promise<void>;
}

export function TeamInvitationForm({ email, role, setEmail, setRole, disabled, onInvite }: TeamInvitationFormProps) {
  const id = useId();
  return <form aria-label="Invite a teammate" className="team-panel__invitation" onSubmit={event => { event.preventDefault(); void onInvite(); }}>
    <h3 className="team-panel__title">Invite a teammate</h3>
    <p className="team-panel__description" id={`${id}-hint`}>Create a private link and share it with the intended person. Access starts only after they accept. A new link for the same email replaces the previous one.</p>
    <fieldset className="team-panel__inviteFields" disabled={disabled}>
      <legend className="team-panel__srOnly">Invitation details</legend>
      <div className="team-panel__field team-panel__field--email">
        <label htmlFor={`${id}-email`}>Email address</label>
        <input id={`${id}-email`} className="team-panel__input" type="email" autoComplete="email" value={email}
          onChange={event => setEmail(event.target.value)} placeholder="Enter email address" required
          maxLength={EMAIL_MAX_LENGTH} pattern={EMAIL_PATTERN} aria-describedby={`${id}-hint`} />
      </div>
      <div className="team-panel__field">
        <label htmlFor={`${id}-role`}>Invite as</label>
        <select id={`${id}-role`} className="team-panel__select" value={role} onChange={event => setRole(event.target.value as WorkspaceRole)}>
          <option value={WorkspaceRole.Normal}>Member</option><option value={WorkspaceRole.WorkspaceAdmin}>Admin</option>
        </select>
      </div>
      <button type="submit" className="team-panel__button team-panel__button--primary" disabled={!email.trim()}>Create invitation link</button>
    </fieldset>
  </form>;
}
