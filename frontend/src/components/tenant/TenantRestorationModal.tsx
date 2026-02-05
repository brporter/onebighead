import { useState, useEffect } from 'react';
import { tenantsApi } from '../../api';
import type { RestorableTenant } from '../../api/tenants';
import '../../styles/components/TenantRestorationModal.css';

interface TenantRestorationModalProps {
  isOpen: boolean;
  onRestoreComplete: () => void;
  onCreateNew: () => void;
}

export function TenantRestorationModal({
  isOpen,
  onRestoreComplete,
  onCreateNew
}: TenantRestorationModalProps) {
  const [restorableTenants, setRestorableTenants] = useState<RestorableTenant[]>([]);
  const [selectedTenantIds, setSelectedTenantIds] = useState<Set<number>>(new Set());
  const [choice, setChoice] = useState<'restore' | 'create'>('restore');
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      loadRestorableTenants();
    }
  }, [isOpen]);

  const loadRestorableTenants = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const tenants = await tenantsApi.getRestorableTenants();
      setRestorableTenants(tenants);
      if (tenants.length > 0) {
        setSelectedTenantIds(new Set([tenants[0].tenantId]));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load tenants');
    } finally {
      setIsLoading(false);
    }
  };

  const toggleTenant = (tenantId: number) => {
    const newSet = new Set(selectedTenantIds);
    if (newSet.has(tenantId)) {
      newSet.delete(tenantId);
    } else {
      newSet.add(tenantId);
    }
    setSelectedTenantIds(newSet);
  };

  const handleContinue = async () => {
    if (choice === 'create') {
      onCreateNew();
      return;
    }

    if (selectedTenantIds.size === 0) {
      setError('Please select at least one workspace to restore');
      return;
    }

    setIsSubmitting(true);
    setError(null);
    try {
      await tenantsApi.restoreTenants({
        tenantIds: Array.from(selectedTenantIds)
      });
      onRestoreComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to restore workspaces');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!isOpen) return null;

  console.log('[TenantRestorationModal] Rendering modal, isLoading:', isLoading, 'tenants:', restorableTenants.length);

  return (
    <div className="restoration-modal-overlay">
      <div className="restoration-modal">
        <h2 className="restoration-modal__title">Welcome Back</h2>
        <p className="restoration-modal__description">
          Your account has been restored. Choose how you'd like to continue:
        </p>

        {error && <div className="restoration-modal__error">{error}</div>}

        {isLoading ? (
          <div className="restoration-modal__loading">Loading...</div>
        ) : (
          <>
            <div className="restoration-modal__options">
              <label className="restoration-modal__option">
                <input
                  type="radio"
                  name="choice"
                  checked={choice === 'restore'}
                  onChange={() => setChoice('restore')}
                />
                <span>Restore existing workspace(s)</span>
              </label>

              {choice === 'restore' && restorableTenants.length > 0 && (
                <div className="restoration-modal__tenants">
                  {restorableTenants.map(tenant => (
                    <label key={tenant.tenantId} className="restoration-modal__tenant">
                      <input
                        type="checkbox"
                        checked={selectedTenantIds.has(tenant.tenantId)}
                        onChange={() => toggleTenant(tenant.tenantId)}
                      />
                      <div className="restoration-modal__tenant-info">
                        <span className="restoration-modal__tenant-name">{tenant.name}</span>
                        <span className="restoration-modal__tenant-stats">
                          {tenant.stats.collectionCount} collections, {tenant.stats.itemCount} items
                        </span>
                        <span className="restoration-modal__tenant-countdown">
                          {tenant.daysRemaining} days until permanent deletion
                        </span>
                      </div>
                    </label>
                  ))}
                </div>
              )}

              <label className="restoration-modal__option">
                <input
                  type="radio"
                  name="choice"
                  checked={choice === 'create'}
                  onChange={() => setChoice('create')}
                />
                <span>Create a new workspace</span>
              </label>
            </div>

            <button
              className="restoration-modal__button"
              onClick={handleContinue}
              disabled={isSubmitting || (choice === 'restore' && selectedTenantIds.size === 0)}
            >
              {isSubmitting ? 'Processing...' : 'Continue'}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

export default TenantRestorationModal;
