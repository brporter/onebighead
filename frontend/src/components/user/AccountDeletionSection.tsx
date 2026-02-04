import React, { useState, useEffect, useCallback } from 'react';
import { DeletionConfirmationModal, type TenantBlocker } from '../common';
import {
  accountApi,
  DeletionBlockerReason,
  TenantActionType,
  type UserDeletionInfo,
  type TenantActionRequest
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
  const [blockers, setBlockers] = useState<TenantBlocker[]>([]);

  const loadDeletionInfo = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const info = await accountApi.getDeletionInfo();
      setDeletionInfo(info);

      // Convert to blockers format
      const tenantBlockers: TenantBlocker[] = info.tenantMemberships
        .filter(m => !m.canLeave)
        .map(m => ({
          tenantId: m.tenantId,
          tenantName: m.tenantName,
          reason: m.blockerReason,
          users: m.otherUsers,
          resolved: false,
        }));

      setBlockers(tenantBlockers);
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

  const handleResolveBlocker = (tenantId: number, action: TenantActionType, userId?: number) => {
    setBlockers(prev => prev.map(b => {
      if (b.tenantId !== tenantId) return b;
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

    // Build tenant actions from resolved blockers
    const tenantActions: TenantActionRequest[] = blockers
      .filter(b => b.resolved && b.action)
      .map(b => ({
        tenantId: b.tenantId,
        action: b.action!,
        transferToUserId: b.transferToUserId,
      }));

    const result = await accountApi.deleteAccount({
      confirmEmail: deletionInfo.email,
      tenantActions,
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
      const tenantBlockers: TenantBlocker[] = deletionInfo.tenantMemberships
        .filter(m => !m.canLeave)
        .map(m => ({
          tenantId: m.tenantId,
          tenantName: m.tenantName,
          reason: m.blockerReason,
          users: m.otherUsers,
          resolved: false,
        }));
      setBlockers(tenantBlockers);
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
