import type { ReactNode } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { useUser } from '../../contexts/useUser';
import { workspacesApi } from '../../api';
import { useWorkspaceRecovery } from '../../data/workspaces/useWorkspaceRecovery';
import { WorkspaceRestorationModal } from '../workspace/WorkspaceRestorationModal';
import { ContentState } from './ContentState';

/** Checks recovery once per identity before rendering workspace-dependent routes. */
export function NoWorkspaceHandler({ children }: { children: ReactNode }) {
  const { user, loading } = useUser();
  if (loading) return <ContentState kind="loading" title="Checking your workspaces…" />;
  if (!user) return <>{children}</>;
  return <WorkspaceGate key={user.userId} needed={user.workspaces.length === 0}>{children}</WorkspaceGate>;
}

function WorkspaceGate({ needed, children }: { needed: boolean; children: ReactNode }) {
  const navigate = useNavigate();
  const { refetch } = useUser();
  const editor = useWorkspaceRecovery(needed, workspacesApi, () => refetch({ throwOnError: true }), () => navigate('/collections', { replace: true }));
  const createNew = () => navigate('/workspaces/new', { replace: true });
  if (!needed && !editor.pending) return <>{children}</>;
  const { recovery } = editor;
  if (recovery.error) return <ContentState kind="error" title="Unable to check recoverable workspaces" action={<>
    <button type="button" onClick={recovery.retry}>Try again</button>
    <button type="button" onClick={createNew}>Create a new workspace</button>
  </>}>{recovery.error}</ContentState>;
  if (recovery.data === null) return <ContentState kind="loading" title="Checking your workspaces…" />;
  if (recovery.data.length === 0) return <Navigate to="/workspaces/new" replace />;
  return <WorkspaceRestorationModal {...editor} onCreateNew={createNew} onReload={recovery.retry} />;
}

export default NoWorkspaceHandler;
