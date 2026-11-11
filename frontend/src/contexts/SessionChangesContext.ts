import { createContext } from 'react';
import type { SessionChanges } from '../data/auth/SessionChanges';

export const SessionChangesContext = createContext<SessionChanges | null>(null);
