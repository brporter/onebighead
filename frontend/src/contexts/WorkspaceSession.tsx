import { useEffect, useRef, type ReactNode } from 'react';
import { useUser } from './useUser';
import { DataProvider } from './DataContext';

/** Retire workspace data, pending workflows and route drafts when identity changes. */
export function WorkspaceSession({ children, navigate }: {
  children: ReactNode;
  navigate: (path: string) => void | Promise<void>;
}) {
  const { user } = useUser();
  const scope = user ? `${user.userId}:${user.activeWorkspace?.workspaceId ?? user.workspaceId}` : null;
  const previous = useRef(scope);
  useEffect(() => {
    const old = previous.current;
    previous.current = scope;
    // Initial sign-in preserves the requested deep link. Later scope changes need a new route.
    if (old !== null && scope !== null && old !== scope) void navigate('/collections');
  }, [scope, navigate]);
  return <DataProvider key={scope}>{children}</DataProvider>;
}
