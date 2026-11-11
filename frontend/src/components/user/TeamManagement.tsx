import { useTeamMembers } from '../../data/team/useTeamMembers';
import type { TeamPort } from '../../data/team/ports';
import { teamRemovalConfirmation } from '../../data/team/teamPolicy';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import { ContentState } from '../common/ContentState';
import { TeamInvitationForm } from './TeamInvitationForm';
import { TeamMemberList } from './TeamMemberList';
import { useTeamInvitations } from '../../data/invitations/useTeamInvitations';
import { InvitationLink } from './InvitationLink';
import { PendingInvitations } from './PendingInvitations';
import '../../styles/components/TeamManagement.css';

interface TeamManagementProps {
  currentUserId: number;
  gateway: TeamPort;
  onStatusChange?: EditorStatusListener;
}

export function TeamManagement({ currentUserId, gateway, onStatusChange }: TeamManagementProps) {
  const team = useTeamMembers(currentUserId, gateway);
  const invitations = useTeamInvitations(gateway);
  const pending = team.pending || invitations.pending;
  useEditorStatus(invitations.dirty, pending, onStatusChange);
  const disabled = pending || team.loading || team.users === null;
  const retry = <button type="button" className="team-panel__button" disabled={team.pending} onClick={() => void team.refresh()}>Refresh team</button>;
  const retryInvitations = <button type="button" className="team-panel__button" disabled={pending} onClick={() => void invitations.refresh()}>Refresh invitations</button>;
  return <div className="team-panel" aria-busy={pending}>
    <TeamInvitationForm email={invitations.email} role={invitations.role} setEmail={invitations.setEmail} setRole={invitations.setRole}
      disabled={disabled || invitations.loading || invitations.invitations === null} onInvite={invitations.invite} />
    {invitations.error && <p className="team-panel__error" role="alert">{invitations.error}</p>}
    {invitations.message && <p className="team-panel__notice" role="status">{invitations.message}</p>}
    {invitations.created && <InvitationLink key={invitations.created.token} created={invitations.created} />}
    {invitations.invitations === null ? <ContentState kind={invitations.loading ? 'loading' : 'error'}
      title={invitations.loading ? 'Loading invitations…' : 'Unable to load invitations'}
      action={invitations.loading ? undefined : retryInvitations}>{invitations.loadError}</ContentState> : <>
      {invitations.loadError && <ContentState kind="error" title="Unable to refresh invitations" action={retryInvitations}>{invitations.loadError}</ContentState>}
      <PendingInvitations invitations={invitations.invitations} disabled={disabled || invitations.loading}
        onRenew={invitation => { if (window.confirm('Create a new invitation link? The previous link will stop working.')) void invitations.renew(invitation); }}
        onCancel={id => { if (window.confirm('Cancel this invitation? Its link will stop working.')) void invitations.cancel(id); }} />
    </>}
    {team.error && <p className="team-panel__error" role="alert">{team.error}</p>}
    {team.message && <p className="team-panel__notice" role="status">{team.message}</p>}
    {team.users === null ? <ContentState kind={team.loading ? 'loading' : 'error'}
      title={team.loading ? 'Loading team members...' : 'Unable to load team members'}
      action={team.loading ? undefined : retry}>{team.loadError}</ContentState> : <>
      {team.loadError && <ContentState kind="error" title="Unable to refresh team members" action={retry}>
        <p>{team.loadError}</p><p>Confirmed changes are shown below. Refreshing will not repeat them.</p>
      </ContentState>}
      {team.loading && <p className="team-panel__notice" role="status">Refreshing team members…</p>}
      <TeamMemberList users={team.users} currentUserId={currentUserId} disabled={disabled}
        onRoleChange={team.changeRole} onRemove={member => {
          if (window.confirm(teamRemovalConfirmation(member))) void team.remove(member.userId);
        }} />
    </>}
    <div className="team-panel__legend">
      <p><strong>Admin:</strong> Can create collections, templates, invite users, and export data.</p>
      <p><strong>Member:</strong> Can create and edit items and categories.</p>
    </div>
  </div>;
}
