import { WorkspaceRole, type CurrentUser, type WorkspaceUser } from '../../src/utils/types';

export const teamMember = (overrides: Partial<WorkspaceUser> = {}): WorkspaceUser => ({
  userId: 2, email: 'member@example.com', workspaceRole: WorkspaceRole.Normal, isLinked: true,
  identityProvider: 'Microsoft', createdAt: '2026-11-01T00:00:00Z', ...overrides,
});
export const team = () => [
  teamMember({ userId: 1, email: 'admin@example.com', workspaceRole: WorkspaceRole.WorkspaceAdmin }),
  teamMember(),
  teamMember({ userId: 3, email: 'pending@example.com', isLinked: false, identityProvider: null }),
];
export function teamAdministrator(workspaceId = 1, userId = 1): CurrentUser {
  const activeWorkspace = { workspaceId, workspaceName: 'Library', workspaceRole: WorkspaceRole.WorkspaceAdmin, hasCompletedWelcome: true };
  return { userId, email: 'admin@example.com', workspaceId, workspaceName: 'Library', workspaceRole: WorkspaceRole.WorkspaceAdmin,
    activeWorkspace, workspaces: [activeWorkspace], isWorkspaceAdmin: true, isSystemAdministrator: false,
    hasCompletedWelcome: true, hasAcceptedTerms: true };
}

export const invitation = () => ({ invitationId: 'a1234567-1234-1234-1234-123456789abc', email: 'new@example.com', role: WorkspaceRole.Normal, createdAt: '2026-11-11T00:00:00Z', expiresAt: '2026-11-18T00:00:00Z' });
export const createdInvitation = () => ({ invitation: invitation(), token: 'a'.repeat(64) });
