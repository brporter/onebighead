import { useState } from 'react';
import { type WorkspaceRole, type WorkspaceUser } from '../../utils/types';
import { useRemoteResource } from '../shared/useRemoteResource';
import { useAsyncAction } from '../../utils/useAsyncAction';
import type { TeamMembersPort } from './ports';
import { requireTeamEdit, validateTeamRole } from './teamPolicy';

interface TeamChange { users: WorkspaceUser[]; message: string }

/** One mounted workspace session owns the draft, confirmed team and ordered actions. */
export function useTeamMembers(currentUserId: number, gateway: TeamMembersPort) {
  const resource = useRemoteResource(gateway.getUsers, 'Failed to load team members');
  const { reload } = resource;
  const action = useAsyncAction();
  const [message, setMessage] = useState<string | null>(null);

  const requireUsers = () => {
    if (resource.data === null) throw new Error('Load the team before making changes.');
    return resource.data;
  };
  const accepted = async (change: TeamChange) => {
    resource.setData(change.users);
    setMessage(change.message);
    // The write is confirmed. A read failure retains that state and retries only the read.
    await reload();
  };

  return {
    users: resource.data, loading: resource.loading, loadError: resource.error,
    pending: action.pending, error: action.error, message,
    refresh: () => action.run(reload, 'Failed to refresh team members'),
    changeRole: (id: number, nextRole: WorkspaceRole) => action.run(async () => {
      const users = requireUsers();
      const member = requireTeamEdit(users, id, currentUserId);
      validateTeamRole(nextRole);
      await gateway.updateUserRole(id, nextRole);
      return { users: users.map(user => user.userId === id ? { ...user, workspaceRole: nextRole } : user), message: `Role updated for ${member.email}.` };
    }, 'Failed to update user role', accepted),
    remove: (id: number) => action.run(async () => {
      const users = requireUsers();
      const member = requireTeamEdit(users, id, currentUserId);
      await gateway.removeUser(id);
      return { users: users.filter(user => user.userId !== id), message: `${member.email} was removed from the team.` };
    }, 'Failed to remove user', accepted),
  };
}
