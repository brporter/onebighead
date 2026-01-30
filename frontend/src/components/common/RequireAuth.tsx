import { Navigate, useLocation } from 'react-router-dom';
import { useUser } from '../../contexts/UserContext';

interface RequireAuthProps {
  children: React.ReactNode;
  /** Skip the welcome redirect check (used for the /welcome route itself) */
  skipWelcomeCheck?: boolean;
}

/**
 * Wrapper component that redirects unauthenticated users to the sign-in page.
 * Also redirects first-time users to the welcome wizard.
 * Preserves the original URL so users can be redirected back after login.
 */
function RequireAuth({ children, skipWelcomeCheck = false }: RequireAuthProps) {
  const { user, loading } = useUser();
  const location = useLocation();

  if (loading) {
    return <div className="app__loading">Loading...</div>;
  }

  if (!user) {
    // Redirect to signin, preserving the intended destination
    const returnUrl = encodeURIComponent(location.pathname + location.search);
    window.location.href = `/signin?returnUrl=${returnUrl}`;
    return null;
  }

  // Redirect to welcome wizard if user hasn't completed welcome
  if (!skipWelcomeCheck && !user.hasCompletedWelcome) {
    return <Navigate to="/welcome" replace />;
  }

  return <>{children}</>;
}

export default RequireAuth;
