import type { WorkspaceRole } from '../../utils/types';

export interface WorkspaceInvitation {
  invitationId: string;
  email: string;
  role: WorkspaceRole;
  createdAt: string;
  expiresAt: string;
}
export interface CreatedInvitation { invitation: WorkspaceInvitation; token: string }
export interface InvitationAccess { invitationId: string; token: string }
export interface InvitationPreview { workspaceName: string; email: string; role: WorkspaceRole; expiresAt: string }
