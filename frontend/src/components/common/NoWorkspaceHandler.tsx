import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '../../contexts/useUser';
import { workspacesApi } from '../../api';
import { WorkspaceRestorationModal } from '../workspace';

interface NoWorkspaceHandlerProps {
  children: React.ReactNode;
}

/**
 * Handles the case where a user has no active workspace.
 * Shows restoration modal if user has restorable workspaces,
 * otherwise redirects to workspace creation.
 */
export function NoWorkspaceHandler({ children }: NoWorkspaceHandlerProps) {
  const { user, loading, refetch } = useUser();
  const navigate = useNavigate();
  const [showRestorationModal, setShowRestorationModal] = useState(false);
  const [hasCheckedWorkspaces, setHasCheckedWorkspaces] = useState(false);
  const [isCheckingWorkspaces, setIsCheckingWorkspaces] = useState(false);
  const isCheckingRef = useRef(false);

  useEffect(() => {
    const checkWorkspaceStatus = async () => {
      console.log('[NoWorkspaceHandler] checkWorkspaceStatus:', {
        loading,
        hasUser: !!user,
        hasCheckedWorkspaces,
        isChecking: isCheckingRef.current
      });
      if (loading || !user || hasCheckedWorkspaces || isCheckingRef.current) return;

      // Check if user has no active workspaces (all workspaces array is empty or all deleted)
      const activeWorkspaces = user.workspaces || [];
      console.log('[NoWorkspaceHandler] User workspaces:', activeWorkspaces);

      if (activeWorkspaces.length === 0) {
        // Check for restorable workspaces
        console.log('[NoWorkspaceHandler] No active workspaces, checking for restorable workspaces...');
        isCheckingRef.current = true;
        setIsCheckingWorkspaces(true);
        try {
          const restorable = await workspacesApi.getRestorableWorkspaces();
          console.log('[NoWorkspaceHandler] Restorable workspaces response:', restorable);
          if (restorable.length > 0) {
            console.log('[NoWorkspaceHandler] Found restorable workspaces, showing modal');
            setShowRestorationModal(true);
          } else {
            // No restorable workspaces - redirect to workspace creation
            console.log('[NoWorkspaceHandler] No restorable workspaces, redirecting to /workspaces/new');
            navigate('/workspaces/new');
          }
        } catch (error) {
          // On error, redirect to workspace creation
          console.error('[NoWorkspaceHandler] Error fetching restorable workspaces:', error);
          navigate('/workspaces/new');
        } finally {
          isCheckingRef.current = false;
          setIsCheckingWorkspaces(false);
        }
      }
      setHasCheckedWorkspaces(true);
    };

    checkWorkspaceStatus();
  }, [user, loading, hasCheckedWorkspaces, navigate]);

  const handleRestoreComplete = () => {
    setShowRestorationModal(false);
    refetch();
    navigate('/collections');
  };

  const handleCreateNew = () => {
    setShowRestorationModal(false);
    navigate('/workspaces/new');
  };

  // While checking for restorable workspaces with no active workspaces, show loading
  // This prevents children from rendering and navigating away
  const hasNoWorkspaces = user && (!user.workspaces || user.workspaces.length === 0);
  if (hasNoWorkspaces && (isCheckingWorkspaces || (!hasCheckedWorkspaces && !showRestorationModal))) {
    return <div className="app__loading">Loading...</div>;
  }

  // If showing restoration modal, don't render children (prevent navigation)
  if (showRestorationModal) {
    return (
      <WorkspaceRestorationModal
        isOpen={true}
        onRestoreComplete={handleRestoreComplete}
        onCreateNew={handleCreateNew}
      />
    );
  }

  return <>{children}</>;
}

export default NoWorkspaceHandler;
