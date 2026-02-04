import React, { useState, useCallback } from 'react';
import { DeletionConfirmationModal } from '../common';
import { tenantsApi, exportApi } from '../../api';
import type { TenantStats } from '../../api/tenants';
import type { TenantMembership } from '../../utils/types';

interface TenantDeletionSectionProps {
  tenant: TenantMembership;
  onDeleted: () => void;
}

export function TenantDeletionSection({ tenant, onDeleted }: TenantDeletionSectionProps) {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [stats, setStats] = useState<TenantStats | null>(null);
  const [isLoadingStats, setIsLoadingStats] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDeleteClick = async () => {
    setIsLoadingStats(true);
    setError(null);
    try {
      const tenantStats = await tenantsApi.getStats(tenant.tenantId);
      setStats(tenantStats);
      setIsModalOpen(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load workspace statistics');
    } finally {
      setIsLoadingStats(false);
    }
  };

  const handleExport = async () => {
    setIsExporting(true);
    try {
      const { blob, filename } = await exportApi.downloadExport();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } finally {
      setIsExporting(false);
    }
  };

  const handleConfirmDelete = useCallback(async () => {
    const result = await tenantsApi.deleteTenant(tenant.tenantId);
    if (!result.success) {
      throw new Error('Failed to delete workspace');
    }
    onDeleted();
  }, [tenant.tenantId, onDeleted]);

  return (
    <>
      {error && <div className="settings-section__error">{error}</div>}
      <button
        className="settings-tenant-card__button settings-tenant-card__button--danger"
        onClick={handleDeleteClick}
        disabled={isLoadingStats}
      >
        {isLoadingStats ? 'Loading...' : 'Delete'}
      </button>

      <DeletionConfirmationModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onConfirm={handleConfirmDelete}
        title={`Delete "${tenant.tenantName}"`}
        entityType="tenant"
        entityName={tenant.tenantName}
        stats={stats ? {
          collections: stats.collectionCount,
          categories: stats.categoryCount,
          items: stats.itemCount,
          images: stats.imageCount,
          users: stats.userCount,
        } : undefined}
        showExportOption={true}
        onExport={handleExport}
        isExporting={isExporting}
        confirmationType="checkbox"
      />
    </>
  );
}

export default TenantDeletionSection;
