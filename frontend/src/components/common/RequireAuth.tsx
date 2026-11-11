import React, { useEffect } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useUser } from '../../contexts/useUser';
import { ContentState } from './ContentState';

interface RequireAuthProps {
  children: React.ReactNode;
  /** Skip the welcome redirect check (used for the /welcome route itself) */
  skipWelcomeCheck?: boolean;
  /** Skip the terms acceptance redirect check (used for the /terms route itself) */
  skipTermsCheck?: boolean;
}

/**
 * Wrapper component that redirects unauthenticated users to the sign-in page.
 * Also redirects users who haven't accepted terms to the terms page.
 * Also redirects first-time users to the welcome wizard.
 * Preserves the original URL so users can be redirected back after login.
 */
function RequireAuth({ children, skipWelcomeCheck = false, skipTermsCheck = false }: RequireAuthProps) {
  const { user, loading, signedOut, error, refetch } = useUser();
  const location = useLocation();

  const redirectUrl = !loading && !user && !error
    ? signedOut ? '/' : `/signin?returnUrl=${encodeURIComponent(location.pathname + location.search)}`
    : null;

  useEffect(() => {
    if (redirectUrl !== null) {
      globalThis.location.href = redirectUrl;
    }
  }, [redirectUrl]);

  if (loading) {
    return <div className="app__loading">Loading...</div>;
  }

  if (!user) {
    if (error) return <ContentState kind="error" title="Unable to check your session" action={<button type="button" className="content-state__button" onClick={() => { void refetch(); }}>Try again</button>}>{error}</ContentState>;
    return null;
  }

  // Check if user has any workspaces
  const hasAnyWorkspace = user.workspaces && user.workspaces.length > 0;

  // If user has no workspaces, let NoWorkspaceHandler manage the flow
  // Don't redirect to welcome wizard in this case
  if (!hasAnyWorkspace) {
    return <>{children}</>;
  }

  // Only administrators complete workspace setup. Other members still accept
  // their own terms and can use an existing workspace while setup is pending.
  const needsWelcome = user.isWorkspaceAdmin && !user.hasCompletedWelcome;
  if (!skipTermsCheck && !user.hasAcceptedTerms && !needsWelcome) {
    return <Navigate to="/terms" replace />;
  }

  if (!skipWelcomeCheck && needsWelcome) {
    return <Navigate to="/welcome" replace />;
  }

  return <>{children}</>;
}

export default RequireAuth;
