import type { accountApi } from '../../api/account';
import type { SessionChanges } from '../auth/SessionChanges';
import { runSessionMutation } from '../auth/runSessionMutation';

export type AccountDeletionPort = Pick<typeof accountApi, 'getDeletionInfo' | 'deleteAccount'>;

/** A confirmed deletion ends the session; an unknown outcome requires a session read. */
export function createAccountDeletionGateway(
  gateway: AccountDeletionPort,
  changes: SessionChanges,
  refresh: () => Promise<void>,
  confirmDiscard: () => boolean,
): AccountDeletionPort {
  return {
    getDeletionInfo: gateway.getDeletionInfo,
    deleteAccount: async request => {
      try {
        return await runSessionMutation({
          changes, kind: 'account-deletion', refresh, confirmDiscard,
          failure: 'Failed to delete account', cancelled: 'Account deletion cancelled',
          change: async () => {
            const result = await gateway.deleteAccount(request);
            if (!result.success) throw new Error(result.error || 'Failed to delete account');
            return result;
          },
        });
      } catch (cause) {
        // Session feedback owns the transient read error. Keep the underlying
        // dialog's guidance valid after that read has recovered.
        if (changes.getSnapshot().recovery) throw new Error('Review workspace choices before trying account deletion again.');
        throw cause;
      }
    },
  };
}
