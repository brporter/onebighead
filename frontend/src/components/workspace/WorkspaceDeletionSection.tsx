import React, { useState, useCallback } from 'react';
import { DeletionConfirmationModal } from '../common';
import { workspacesApi, exportApi, authApi } from '../../api';
import type { WorkspaceStats } from '../../api/workspaces';
import type { WorkspaceMembership } from '../../utils/types';

interface WorkspaceDeletionSectionProps {
  workspace: WorkspaceMembership;
  onDeleted: () => void;
}

export function WorkspaceDeletionSection({ workspace, onDeleted }: WorkspaceDeletionSectionProps) {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [stats, setStats] = useState<WorkspaceStats | null>(null);
  const [isLoadingStats, setIsLoadingStats] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDeleteClick = async () => {
    setIsLoadingStats(true);
    setError(null);
    try {
      const workspaceStats = await workspacesApi.getStats(workspace.workspaceId);
      setStats(workspaceStats);
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
    const result = await workspacesApi.deleteWorkspace(workspace.workspaceId);
    if (!result.success) {
      throw new Error('Failed to delete workspace');
    }

    if (result.userSoftDeleted) {
      // User account was soft-deleted - log out and redirect to homepage
      await authApi.logout();
      window.location.href = '/';
      return;
    }

    onDeleted();
  }, [workspace.workspaceId, onDeleted]);

  return (
    <>
      {error && <div className="settings-section__error">{error}</div>}
      <button
        className="settings-workspace-card__button settings-workspace-card__button--danger"
        onClick={handleDeleteClick}
        disabled={isLoadingStats}
      >
        {isLoadingStats ? 'Loading...' : 'Delete'}
      </button>

      <DeletionConfirmationModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onConfirm={handleConfirmDelete}
        title={`Delete "${workspace.workspaceName}"`}
        entityType="workspace"
        entityName={workspace.workspaceName}
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

export default WorkspaceDeletionSection;
