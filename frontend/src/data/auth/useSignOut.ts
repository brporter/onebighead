import type { SessionRefreshOptions } from './useUserSession';
import { useSessionChanges } from './useSessionChanges';

interface SignOutPort {
  logout: () => Promise<void>;
  refetch: (options: SessionRefreshOptions) => Promise<void>;
}

/** Shares editor protection and session recovery across sign-out controls. */
export function useSignOut({ logout, refetch }: SignOutPort, leave: () => void) {
  const session = useSessionChanges();
  const { changes, state } = session;
  const busy = state.pending || state.recovery || state.leaving;
  const signOut = async () => {
    const completed = await changes.run('logout', logout, () => refetch({ throwOnError: true }),
      () => window.confirm('You have unsaved changes. Discard them?'));
    if (completed) leave();
  };
  return { changes, managed: session.managed, busy, signOut,
    signingOut: state.kind === 'logout' && busy,
    error: state.kind === 'logout' && !state.recovery ? state.error : null };
}
