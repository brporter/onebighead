import { useContext } from 'react';
import UserContext from './UserContext';
import type { UserContextValue } from './UserContext';

export function useUser(): UserContextValue {
  return useContext(UserContext);
}
