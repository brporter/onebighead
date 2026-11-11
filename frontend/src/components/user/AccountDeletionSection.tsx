import '../../styles/components/AccountDeletionSection.css';
import { useState } from 'react';
import { DeletionConfirmationModal } from '../common/DeletionConfirmationModal';
import { accountApi, type UserDeletionInfo } from '../../api/account';
import { createAccountDeletionBlockers, planAccountDeletion } from '../../data/account/deletionPlan';
import { useAsyncAction } from '../../utils/useAsyncAction';
import { useUser } from '../../contexts/useUser';
import { useSessionChanges } from '../../data/auth/useSessionChanges';
import { createAccountDeletionGateway, type AccountDeletionPort } from '../../data/account/createAccountDeletionGateway';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import { SessionChangeFeedback } from '../common/SessionChangeFeedback';

interface AccountDeletionSectionProps {
  onDeleted?: () => void;
  onStatusChange?: EditorStatusListener;
}

export function AccountDeletionSection({ onDeleted, onStatusChange }: AccountDeletionSectionProps) {
  const { refetch } = useUser();
  const { changes, state, managed } = useSessionChanges();
  const gateway = createAccountDeletionGateway(accountApi, changes,
    () => refetch({ throwOnError: true, endSessionIfAnonymous: true }),
    () => window.confirm('You have unsaved changes. Discard them?'));
  const busy = state.pending || state.recovery || state.leaving;
  useEditorStatus(false, busy, onStatusChange);
  const [info, setInfo] = useState<UserDeletionInfo | null>(null);
  const preparation = useAsyncAction();
  const prepare = () => {
    setInfo(null);
    void preparation.run(gateway.getDeletionInfo, 'Failed to load account information', setInfo);
  };

  return (
    <div className="account-deletion-section">
      <div className="account-deletion-section__header">
        <h3 className="account-deletion-section__title">Delete Account</h3>
        <p className="account-deletion-section__description">
          Permanently remove your account and workspace memberships. Shared collections remain available to their other members.
        </p>
      </div>
      {preparation.error && <div className="settings-section__error" role="alert">{preparation.error}</div>}
      <button
        type="button"
        className="account-deletion-section__button account-deletion-section__button--danger"
        onClick={prepare}
        disabled={preparation.pending || busy}
      >
        {preparation.pending ? 'Loading...' : 'Delete My Account'}
      </button>
      {info && <AccountDeletionDialog info={info} deleteAccount={gateway.deleteAccount} onReview={prepare} onClose={() => setInfo(null)} onDeleted={onDeleted} />}
      {!managed && <SessionChangeFeedback changes={changes} />}
    </div>
  );
}

/** A fresh confirmation session owns its choices and the server-confirmed email. */
function AccountDeletionDialog({ info, deleteAccount, onReview, onClose, onDeleted }: AccountDeletionSectionProps & {
  info: UserDeletionInfo;
  deleteAccount: AccountDeletionPort['deleteAccount'];
  onReview: () => void;
  onClose: () => void;
}) {
  const [blockers, setBlockers] = useState(() => createAccountDeletionBlockers(info));

  async function confirm() {
    await deleteAccount(planAccountDeletion(info.email, blockers));
    // The deletion endpoint already clears the auth cookie. A second logout
    // request must not turn a completed deletion into a retryable failure.
    if (onDeleted) onDeleted();
    else window.location.href = '/';
  }

  return <DeletionConfirmationModal
    isOpen
    onClose={onClose}
    onConfirm={confirm}
    title="Delete Your Account"
    entityType="account"
    entityName={info.email}
    confirmationType="text-match"
    confirmationText={info.email}
    errorAction={{ label: 'Review workspace choices', onClick: onReview }}
    blockers={blockers}
    onResolveBlocker={(workspaceId, action, transferToUserId) => setBlockers(current => current.map(blocker =>
      blocker.workspaceId === workspaceId ? { ...blocker, resolved: true, action, transferToUserId } : blocker))}
  />;
}

export default AccountDeletionSection;
