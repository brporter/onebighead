import { createContext, type ReactNode } from 'react';
import type { CurrentUser } from '../utils/types';
import { authApi } from '../api';
import { useUserSession, type SessionRefreshOptions } from '../data/auth/useUserSession';
import { SessionChangesProvider } from './SessionChangesProvider';

export interface UserContextValue {
  user: CurrentUser | null;
  loading: boolean;
  error: string | null;
  /** Distinguishes an intentional sign-out from an anonymous/expired session. */
  signedOut: boolean;
  refetch: (options?: SessionRefreshOptions) => Promise<void>;
  logout: () => Promise<void>;
}

const UserContext = createContext<UserContextValue | null>(null);

interface UserProviderProps {
  children: ReactNode;
}

export function UserProvider({ children }: UserProviderProps) {
  const session = useUserSession(authApi);

  return (
    <UserContext.Provider value={session}>
      <SessionChangesProvider>{children}</SessionChangesProvider>
    </UserContext.Provider>
  );
}

export default UserContext;
