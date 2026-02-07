import { useState, useCallback } from 'react';
import { DeletionConfirmationModal, type WorkspaceBlocker } from '../common';
import {
  accountApi,
  WorkspaceActionType,
  type UserDeletionInfo,
  type WorkspaceActionRequest
} from '../../api/account';
import { useUser } from '../../contexts/UserContext';

interface AccountDeletionSectionProps {
  onDeleted?: () => void;
}

export function AccountDeletionSection({ onDeleted }: AccountDeletionSectionProps) {
  const { user, logout } = useUser();
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [deletionInfo, setDeletionInfo] = useState<UserDeletionInfo | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [blockers, setBlockers] = useState<WorkspaceBlocker[]>([]);

  const loadDeletionInfo = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const info = await accountApi.getDeletionInfo();
      setDeletionInfo(info);

      // Convert to blockers format
      const workspaceBlockers: WorkspaceBlocker[] = info.workspaceMemberships
        .filter(m => !m.canLeave)
        .map(m => ({
          workspaceId: m.workspaceId,
          workspaceName: m.workspaceName,
          reason: m.blockerReason,
          users: m.otherUsers,
          resolved: false,
        }));

      setBlockers(workspaceBlockers);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load account information');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const handleDeleteClick = async () => {
    await loadDeletionInfo();
    setIsModalOpen(true);
  };

  const handleResolveBlocker = (workspaceId: number, action: WorkspaceActionType, userId?: number) => {
    setBlockers(prev => prev.map(b => {
      if (b.workspaceId !== workspaceId) return b;
      return {
        ...b,
        resolved: true,
        action,
        transferToUserId: userId,
      };
    }));
  };

  const handleConfirmDelete = useCallback(async () => {
    if (!deletionInfo) return;

    // Build workspace actions from resolved blockers
    const workspaceActions: WorkspaceActionRequest[] = blockers
      .filter(b => b.resolved && b.action)
      .map(b => ({
        workspaceId: b.workspaceId,
        action: b.action!,
        transferToUserId: b.transferToUserId,
      }));

    const result = await accountApi.deleteAccount({
      confirmEmail: deletionInfo.email,
      workspaceActions,
    });

    if (!result.success) {
      throw new Error(result.error || 'Failed to delete account');
    }

    // Log out the user and redirect
    if (onDeleted) {
      onDeleted();
    } else {
      await logout();
      window.location.href = '/';
    }
  }, [deletionInfo, blockers, onDeleted, logout]);

  const handleClose = () => {
    setIsModalOpen(false);
    // Reset blockers when closing
    if (deletionInfo) {
      const workspaceBlockers: WorkspaceBlocker[] = deletionInfo.workspaceMemberships
        .filter(m => !m.canLeave)
        .map(m => ({
          workspaceId: m.workspaceId,
          workspaceName: m.workspaceName,
          reason: m.blockerReason,
          users: m.otherUsers,
          resolved: false,
        }));
      setBlockers(workspaceBlockers);
    }
  };

  return (
    <div className="account-deletion-section">
      <div className="account-deletion-section__header">
        <h3 className="account-deletion-section__title">Delete Account</h3>
        <p className="account-deletion-section__description">
          Permanently delete your account and all associated data. This action cannot be undone.
        </p>
      </div>

      {error && <div className="settings-section__error">{error}</div>}

      <button
        className="account-deletion-section__button account-deletion-section__button--danger"
        onClick={handleDeleteClick}
        disabled={isLoading}
      >
        {isLoading ? 'Loading...' : 'Delete My Account'}
      </button>

      <DeletionConfirmationModal
        isOpen={isModalOpen}
        onClose={handleClose}
        onConfirm={handleConfirmDelete}
        title="Delete Your Account"
        entityType="account"
        entityName={user?.email || ''}
        confirmationType="text-match"
        confirmationText={user?.email}
        blockers={blockers}
        onResolveBlocker={handleResolveBlocker}
      />
    </div>
  );
}

export default AccountDeletionSection;
