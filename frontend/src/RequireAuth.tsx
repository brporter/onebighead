import { Navigate, useLocation } from 'react-router-dom';
import { useUser } from './UserContext';

interface RequireAuthProps {
  children: React.ReactNode;
}

/**
 * Wrapper component that redirects unauthenticated users to the sign-in page.
 * Preserves the original URL so users can be redirected back after login.
 */
function RequireAuth({ children }: RequireAuthProps) {
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

  return <>{children}</>;
}

export default RequireAuth;
