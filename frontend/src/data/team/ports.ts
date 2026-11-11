import type { RequestOptions } from '../../api/client';
import type { InviteUserRequest, WorkspaceRole, WorkspaceUser } from '../../utils/types';
import type { CreatedInvitation, WorkspaceInvitation } from '../invitations/types';

export interface TeamMembersPort {
  getUsers: (options?: RequestOptions) => Promise<WorkspaceUser[]>;
  updateUserRole: (userId: number, role: WorkspaceRole) => Promise<void>;
  removeUser: (userId: number) => Promise<void>;
}

export interface TeamInvitationsPort {
  getInvitations: (options?: RequestOptions) => Promise<WorkspaceInvitation[]>;
  inviteUser: (request: InviteUserRequest) => Promise<CreatedInvitation>;
  cancelInvitation: (id: string) => Promise<void>;
}
export type TeamPort = TeamMembersPort & TeamInvitationsPort;
