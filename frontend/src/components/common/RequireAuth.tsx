import { Navigate, useLocation } from 'react-router-dom';
import { useUser } from '../../contexts/UserContext';

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
  const { user, loading } = useUser();
  const location = useLocation();

  console.log('[RequireAuth] State:', {
    loading,
    hasUser: !!user,
    path: location.pathname,
    skipWelcomeCheck,
    skipTermsCheck,
    hasCompletedWelcome: user?.hasCompletedWelcome,
    tenantsCount: user?.tenants?.length
  });

  if (loading) {
    return <div className="app__loading">Loading...</div>;
  }

  if (!user) {
    // Redirect to signin, preserving the intended destination
    const returnUrl = encodeURIComponent(location.pathname + location.search);
    window.location.href = `/signin?returnUrl=${returnUrl}`;
    return null;
  }

  // Check if user has any tenants
  const hasAnyTenant = user.tenants && user.tenants.length > 0;

  // If user has no tenants, let NoTenantHandler manage the flow
  // Don't redirect to welcome wizard in this case
  if (!hasAnyTenant) {
    return <>{children}</>;
  }

  // Redirect to terms acceptance if user hasn't accepted terms
  // (but skip for users who haven't completed welcome - they'll accept terms in the wizard)
  if (!skipTermsCheck && !user.hasAcceptedTerms && user.hasCompletedWelcome) {
    return <Navigate to="/terms" replace />;
  }

  // Redirect to welcome wizard if user hasn't completed welcome
  if (!skipWelcomeCheck && !user.hasCompletedWelcome) {
    return <Navigate to="/welcome" replace />;
  }

  return <>{children}</>;
}

export default RequireAuth;
