import { useId } from 'react';
import { WorkspaceRole, type WorkspaceUser } from '../../utils/types';
import { teamEditRestriction } from '../../data/team/teamPolicy';
import { ContentState } from '../common/ContentState';
import '../../styles/components/TeamManagement.css';

interface TeamMemberListProps {
  users: WorkspaceUser[];
  currentUserId: number;
  disabled: boolean;
  onRoleChange: (id: number, role: WorkspaceRole) => void | Promise<void>;
  onRemove: (member: WorkspaceUser) => void;
}

export function TeamMemberList({ users, currentUserId, disabled, onRoleChange, onRemove }: TeamMemberListProps) {
  const id = useId();
  return <section aria-labelledby={`${id}-title`}>
    <h3 className="team-panel__title" id={`${id}-title`}>Members <span className="team-panel__count">{users.length}</span></h3>
    {users.length === 0 ? <ContentState kind="empty" title="No team members found." /> : <ul className="team-panel__members">
      {users.map(member => {
        const restriction = teamEditRestriction(users, member, currentUserId);
        const roleId = `${id}-${member.userId}`;
        return <li className={`team-panel__member${member.isLinked ? '' : ' team-panel__member--pending'}`} key={member.userId}>
          <div className="team-panel__memberInfo">
            <h4 className="team-panel__email">{member.email}</h4>
            <div className="team-panel__badges">
              {member.userId === currentUserId && <span className="team-panel__badge">You</span>}
              <span className="team-panel__badge">{member.isLinked ? 'Active' : 'Pending'}</span>
              {member.identityProvider && <span>{member.identityProvider}</span>}
            </div>
            {restriction && <p className="team-panel__hint" id={`${roleId}-restriction`}>{restriction}</p>}
          </div>
          <div className="team-panel__memberActions">
            <div className="team-panel__field">
              <label htmlFor={roleId}>Role{' '}<span className="team-panel__srOnly">for {member.email}</span></label>
              <select id={roleId} className="team-panel__select" value={member.workspaceRole} disabled={disabled || Boolean(restriction)}
                aria-describedby={restriction ? `${roleId}-restriction` : undefined}
                onChange={event => void onRoleChange(member.userId, event.target.value as WorkspaceRole)}>
                <option value={WorkspaceRole.Normal}>Member</option><option value={WorkspaceRole.WorkspaceAdmin}>Admin</option>
              </select>
            </div>
            <button type="button" className="team-panel__button team-panel__button--danger" onClick={() => onRemove(member)}
              disabled={disabled || Boolean(restriction)} aria-describedby={restriction ? `${roleId}-restriction` : undefined}
              aria-label={`${member.isLinked ? 'Remove' : 'Cancel invitation for'} ${member.email}`}>
              {member.isLinked ? 'Remove' : 'Cancel invitation'}
            </button>
          </div>
        </li>;
      })}
    </ul>}
  </section>;
}
