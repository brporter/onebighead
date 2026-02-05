import { useState, useEffect, useCallback } from 'react';
import { usersApi } from '../../api';
import { useUser } from '../../contexts/UserContext';
import type { WorkspaceUser } from '../../utils/types';
import { WorkspaceRole } from '../../utils/types';
import '../../styles/UserManagement.css';

interface UserManagementProps {
  onDirtyChange?: (isDirty: boolean) => void;
}

function UserManagement({ onDirtyChange }: UserManagementProps) {
  const { user: currentUser } = useUser();
  const [users, setUsers] = useState<WorkspaceUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<WorkspaceRole>(WorkspaceRole.Normal);
  const [isInviting, setIsInviting] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [updatingUserId, setUpdatingUserId] = useState<number | null>(null);

  const validateEmail = (email: string): boolean => {
    if (!email) return false;
    // RFC 5322 simplified email regex
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const loadUsers = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await usersApi.getUsers();
      setUsers(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load team members');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  useEffect(() => {
    onDirtyChange?.(inviteEmail.trim().length > 0);
  }, [inviteEmail, onDirtyChange]);

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteEmail.trim()) return;

    // Validate email format
    if (!validateEmail(inviteEmail.trim())) {
      setEmailError('Please enter a valid email address');
      return;
    }

    setIsInviting(true);
    setInviteError(null);
    setEmailError(null);

    try {
      await usersApi.inviteUser({ email: inviteEmail.trim(), role: inviteRole });
      setInviteEmail('');
      setInviteRole(WorkspaceRole.Normal);
      await loadUsers();
    } catch (err) {
      setInviteError(err instanceof Error ? err.message : 'Failed to invite user');
    } finally {
      setIsInviting(false);
    }
  };

  const handleRoleChange = async (userId: number, newRole: WorkspaceRole) => {
    if (updatingUserId) return;

    // Confirm demoting admin
    if (newRole === WorkspaceRole.Normal) {
      const adminCount = users.filter(u => u.workspaceRole === WorkspaceRole.WorkspaceAdmin).length;
      const targetUser = users.find(u => u.userId === userId);
      if (targetUser?.workspaceRole === WorkspaceRole.WorkspaceAdmin && adminCount <= 1) {
        alert('Cannot demote the last admin. Promote another user first.');
        return;
      }
    }

    setUpdatingUserId(userId);
    setError(null);

    try {
      await usersApi.updateUserRole(userId, newRole);
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update user role');
    } finally {
      setUpdatingUserId(null);
    }
  };

  const handleRemoveUser = async (userId: number) => {
    const targetUser = users.find(u => u.userId === userId);
    if (!targetUser) return;

    // Check if removing last admin
    const adminCount = users.filter(u => u.workspaceRole === WorkspaceRole.WorkspaceAdmin).length;
    if (targetUser.workspaceRole === WorkspaceRole.WorkspaceAdmin && adminCount <= 1) {
      alert('Cannot remove the last admin. Promote another user first.');
      return;
    }

    const confirmMessage = targetUser.isLinked
      ? `Are you sure you want to remove ${targetUser.email} from the team? They will no longer have access.`
      : `Are you sure you want to cancel the invitation for ${targetUser.email}?`;

    if (!confirm(confirmMessage)) return;

    setUpdatingUserId(userId);
    setError(null);

    try {
      await usersApi.removeUser(userId);
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove user');
    } finally {
      setUpdatingUserId(null);
    }
  };

  if (loading) {
    return (
      <div className="userManagement">
        <div className="userManagement__loading">Loading team members...</div>
      </div>
    );
  }

  return (
    <div className="userManagement">
      <div className="userManagement__header">
        <h3 className="userManagement__title">Team Members</h3>
        <p className="userManagement__description">
          Manage who has access to your collections. Invite team members by email.
        </p>
      </div>

      {error && <div className="userManagement__error">{error}</div>}

      {/* Invite Form */}
      <form className="userManagement__inviteForm" onSubmit={handleInvite}>
        <div className="userManagement__inviteInputs">
          <input
            type="email"
            className={`userManagement__inviteEmail${emailError ? ' userManagement__inviteEmail--error' : ''}`}
            placeholder="Enter email address"
            value={inviteEmail}
            onChange={(e) => {
              setInviteEmail(e.target.value);
              if (emailError) setEmailError(null);
            }}
            disabled={isInviting}
          />
          <select
            className="userManagement__inviteRole"
            value={inviteRole}
            onChange={(e) => setInviteRole(e.target.value as WorkspaceRole)}
            disabled={isInviting}
          >
            <option value={WorkspaceRole.Normal}>Member</option>
            <option value={WorkspaceRole.WorkspaceAdmin}>Admin</option>
          </select>
          <button
            type="submit"
            className="userManagement__inviteButton"
            disabled={isInviting || !inviteEmail.trim()}
          >
            {isInviting ? 'Inviting...' : 'Invite'}
          </button>
        </div>
        {emailError && <div className="userManagement__inviteError">{emailError}</div>}
        {inviteError && <div className="userManagement__inviteError">{inviteError}</div>}
      </form>

      {/* User List */}
      <div className="userManagement__list">
        {users.map((user) => {
          const isCurrentUser = user.userId === currentUser?.userId;
          const isUpdating = updatingUserId === user.userId;

          return (
            <div
              key={user.userId}
              className={`userManagement__user ${!user.isLinked ? 'userManagement__user--pending' : ''}`}
            >
              <div className="userManagement__userInfo">
                <div className="userManagement__userEmail">
                  {user.email}
                  {isCurrentUser && <span className="userManagement__youBadge">You</span>}
                </div>
                <div className="userManagement__userMeta">
                  {!user.isLinked ? (
                    <span className="userManagement__statusBadge userManagement__statusBadge--pending">
                      Pending
                    </span>
                  ) : (
                    <span className="userManagement__statusBadge userManagement__statusBadge--active">
                      Active
                    </span>
                  )}
                  {user.identityProvider && (
                    <span className="userManagement__provider">{user.identityProvider}</span>
                  )}
                </div>
              </div>

              <div className="userManagement__userActions">
                <select
                  className="userManagement__roleSelect"
                  value={user.workspaceRole}
                  onChange={(e) => handleRoleChange(user.userId, e.target.value as WorkspaceRole)}
                  disabled={isCurrentUser || isUpdating}
                  title={isCurrentUser ? "You cannot change your own role" : undefined}
                >
                  <option value={WorkspaceRole.Normal}>Member</option>
                  <option value={WorkspaceRole.WorkspaceAdmin}>Admin</option>
                </select>

                <button
                  className="userManagement__removeButton"
                  onClick={() => handleRemoveUser(user.userId)}
                  disabled={isCurrentUser || isUpdating}
                  title={isCurrentUser ? "You cannot remove yourself" : "Remove user"}
                >
                  {isUpdating ? '...' : 'Remove'}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      <div className="userManagement__legend">
        <p><strong>Admin:</strong> Can create collections, templates, invite users, and export data.</p>
        <p><strong>Member:</strong> Can create and edit items and categories.</p>
      </div>
    </div>
  );
}

export default UserManagement;
