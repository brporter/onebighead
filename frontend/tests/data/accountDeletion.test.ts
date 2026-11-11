import { expect, it } from 'vitest';
import { planAccountDeletion, type AccountDeletionBlocker } from '../../src/data/account/deletionPlan';
import { DeletionBlockerReason, WorkspaceActionType } from '../../src/api/account';

const blocker: AccountDeletionBlocker = { workspaceId: 4, workspaceName: 'Library', reason: DeletionBlockerReason.SoleUser };

it('rejects incomplete workspace decisions instead of dropping them from the request', () => {
  expect(() => planAccountDeletion('me@example.com', [blocker])).toThrow('Resolve every workspace');
  expect(() => planAccountDeletion('me@example.com', [{ ...blocker, resolved: true }])).toThrow('Resolve every workspace');
  expect(planAccountDeletion('me@example.com', [{ ...blocker, resolved: true, action: WorkspaceActionType.Delete }])).toEqual({
    confirmEmail: 'me@example.com', workspaceActions: [{ workspaceId: 4, action: WorkspaceActionType.Delete }],
  });
});
