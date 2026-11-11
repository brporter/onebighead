import type { DeletionBlockerReason, DeleteAccountRequest, UserBasicInfo, UserDeletionInfo, WorkspaceActionType } from '../../api/account';

export interface AccountDeletionBlocker {
  workspaceId: number;
  workspaceName: string;
  reason: DeletionBlockerReason;
  users?: UserBasicInfo[];
  resolved?: boolean;
  action?: WorkspaceActionType;
  transferToUserId?: number;
}

export function createAccountDeletionBlockers(info: UserDeletionInfo): AccountDeletionBlocker[] {
  return info.workspaceMemberships.filter(membership => !membership.canLeave).map(membership => ({
    workspaceId: membership.workspaceId,
    workspaceName: membership.workspaceName,
    reason: membership.blockerReason,
    users: membership.otherUsers,
    resolved: false,
  }));
}

/** Do not silently omit unresolved workspaces from a destructive request. */
export function planAccountDeletion(email: string, blockers: AccountDeletionBlocker[]): DeleteAccountRequest {
  return { confirmEmail: email, workspaceActions: blockers.map(blocker => {
    if (!blocker.resolved || !blocker.action) throw new Error('Resolve every workspace before deleting your account');
    return { workspaceId: blocker.workspaceId, action: blocker.action, transferToUserId: blocker.transferToUserId };
  }) };
}
