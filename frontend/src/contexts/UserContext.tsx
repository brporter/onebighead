import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import type { CurrentUser } from '../utils/types';
import { authApi } from '../api';
import { getErrorMessage, logError } from '../utils/errorUtils';

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

  const fetchUser = useCallback(async () => {
    try {
      setError(null);
      const data = await authApi.getCurrentUser();
      setUser(data);
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to fetch user'));
      setUser(null);
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
      setUser(null);
    } catch (err) {
      logError('Logout failed', err);
    }
  }, []);

  useEffect(() => {
    fetchUser().finally(() => setLoading(false));
  }, [fetchUser]);

  return (
    <UserContext.Provider value={{ user, loading, error, refetch: fetchUser, logout }}>
      {children}
    </UserContext.Provider>
  );
}

export default UserContext;
