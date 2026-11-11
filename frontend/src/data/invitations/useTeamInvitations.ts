import { useState } from 'react';
import { WorkspaceRole } from '../../utils/types';
import { useAsyncAction } from '../../utils/useAsyncAction';
import { useRemoteResource } from '../shared/useRemoteResource';
import { prepareInvitation } from '../team/teamPolicy';
import type { TeamInvitationsPort } from '../team/ports';
import type { CreatedInvitation, WorkspaceInvitation } from './types';

export function useTeamInvitations(gateway: TeamInvitationsPort) {
  const resource = useRemoteResource(gateway.getInvitations, 'Failed to load invitations');
  const action = useAsyncAction();
  const [email, setEmail] = useState('');
  const [role, setRole] = useState(WorkspaceRole.Normal);
  const [created, setCreated] = useState<CreatedInvitation | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const requireList = () => {
    if (resource.data === null) throw new Error('Load invitations before making changes.');
    return resource.data;
  };
  const create = (address: string, selectedRole: WorkspaceRole) => action.run(async () => {
    const invitations = requireList();
    const result = await gateway.inviteUser(prepareInvitation(address, selectedRole));
    return { result, invitations };
  }, 'Failed to create invitation', async ({ result, invitations }) => {
    resource.setData([...invitations.filter(invitation => invitation.invitationId !== result.invitation.invitationId), result.invitation]);
    setCreated(result);
    setEmail('');
    setRole(WorkspaceRole.Normal);
    setMessage('Invitation link created. Share it privately with the intended person.');
    await resource.reload();
  });
  return {
    invitations: resource.data, loading: resource.loading, loadError: resource.error,
    pending: action.pending, error: action.error, message, created,
    email, setEmail, role, setRole, dirty: email.length > 0 || role !== WorkspaceRole.Normal,
    refresh: () => action.run(resource.reload, 'Failed to refresh invitations'),
    invite: () => create(email, role),
    renew: (invitation: WorkspaceInvitation) => create(invitation.email, invitation.role),
    cancel: (id: string) => action.run(async () => {
      const invitations = requireList();
      await gateway.cancelInvitation(id);
      return invitations.filter(invitation => invitation.invitationId !== id);
    }, 'Failed to cancel invitation', async invitations => {
      resource.setData(invitations);
      if (created?.invitation.invitationId === id) setCreated(null);
      setMessage('Invitation cancelled. Its link can no longer be used.');
      await resource.reload();
    }),
  };
}
