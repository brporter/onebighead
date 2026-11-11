import { useEffect, useState, useSyncExternalStore } from 'react';
import { createPublicationSession, type PublicationSessionOptions } from './publicationSession';

/** The owner keys this component by request ID, so callbacks stay bound to one workspace/request. */
export function usePublicationSession(options: PublicationSessionOptions) {
  const [session] = useState(() => createPublicationSession(options));
  const state = useSyncExternalStore(session.subscribe, session.getSnapshot);
  useEffect(() => { session.start(); return session.stop; }, [session]);
  return { state, session };
}
