import { usersApi } from '../../api/users';
import { useUser } from '../../contexts/useUser';
import type { EditorStatusListener } from '../../data/shared/useEditorStatus';
import { ContentState } from '../common/ContentState';
import { TeamManagement } from './TeamManagement';

export interface UserManagementProps { onStatusChange?: EditorStatusListener }

/** Composes the active identity and API adapter; team state remains workspace-local. */
export default function UserManagement({ onStatusChange }: UserManagementProps) {
  const { user } = useUser();
  if (!user?.isWorkspaceAdmin) return <ContentState kind="error" title="Workspace administrator access is required." />;
  const workspaceId = user.activeWorkspace?.workspaceId ?? user.workspaceId;
  return <TeamManagement key={`${user.userId}:${workspaceId}`} currentUserId={user.userId} gateway={usersApi} onStatusChange={onStatusChange} />;
}
