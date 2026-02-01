import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import type { CurrentUser } from '../utils/types';
import { authApi, ApiError } from '../api';

/**
 * Extract a user-friendly error message from an error, preserving status code for API errors.
 */
function getErrorMessage(error: unknown, defaultMessage: string): string {
  if (error instanceof ApiError) {
    const statusInfo = error.status ? ` (${error.status})` : '';
    return `${error.message}${statusInfo}`;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return defaultMessage;
}

/**
 * Log an error with context, including status code for API errors.
 */
function logError(context: string, error: unknown): void {
  if (error instanceof ApiError) {
    console.error(`${context}: ${error.message} (status: ${error.status})`);
  } else {
    console.error(`${context}:`, error);
  }
}

interface UserContextValue {
  user: CurrentUser | null;
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  logout: () => Promise<void>;
}

const UserContext = createContext<UserContextValue>({
  user: null,
  loading: true,
  error: null,
  refetch: async () => {},
  logout: async () => {},
});

// eslint-disable-next-line react-refresh/only-export-components
export function useUser(): UserContextValue {
  return useContext(UserContext);
}

interface UserProviderProps {
  children: ReactNode;
}

export function UserProvider({ children }: UserProviderProps) {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchUser = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await authApi.getCurrentUser();
      setUser(data);
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to fetch user'));
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
      setUser(null);
    } catch (err) {
      logError('Logout failed', err);
    }
  }, []);

  useEffect(() => {
    fetchUser();
  }, []);

  return (
    <UserContext.Provider value={{ user, loading, error, refetch: fetchUser, logout }}>
      {children}
    </UserContext.Provider>
  );
}

export default UserContext;
