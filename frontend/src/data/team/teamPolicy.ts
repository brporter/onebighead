import { isValidEmail } from '../../utils/email';
import { WorkspaceRole, type InviteUserRequest, type WorkspaceUser } from '../../utils/types';

export function validateTeamRole(role: WorkspaceRole) {
  if (role !== WorkspaceRole.Normal && role !== WorkspaceRole.WorkspaceAdmin) throw new Error('Choose a valid team role.');
}

export function prepareInvitation(email: string, role: WorkspaceRole): InviteUserRequest {
  const normalized = email.trim();
  if (!isValidEmail(normalized)) throw new Error('Please enter a valid email address');
  validateTeamRole(role);
  return { email: normalized, role };
}

/** These immediate UI safeguards complement the server's atomic authorization checks. */
export function teamEditRestriction(users: WorkspaceUser[], target: WorkspaceUser, currentUserId: number): string | null {
  if (target.userId === currentUserId) return 'You cannot change your own role or remove yourself.';
  if (target.workspaceRole === WorkspaceRole.WorkspaceAdmin && users.filter(user => user.workspaceRole === WorkspaceRole.WorkspaceAdmin).length <= 1)
    return 'Promote another member before changing or removing the last admin.';
  return null;
}

export function requireTeamEdit(users: WorkspaceUser[], targetId: number, currentUserId: number): WorkspaceUser {
  const target = users.find(user => user.userId === targetId);
  if (!target) throw new Error('This person is no longer in the team. Refresh the list and try again.');
  const restriction = teamEditRestriction(users, target, currentUserId);
  if (restriction) throw new Error(restriction);
  return target;
}

export function teamRemovalConfirmation(member: WorkspaceUser): string {
  return member.isLinked
    ? `Remove ${member.email} from this workspace? They will lose access to its collections.`
    : `Cancel the invitation for ${member.email}?`;
}
