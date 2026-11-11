import { createContext, useState, useCallback, useMemo, useRef, type ReactNode } from 'react';
import type { EntityRef, PublishIntent } from '../utils/types';
import type { PublicationRequest } from '../data/publishing/publicationSession';
import { useUser } from './useUser';

export interface PublishContextValue {
  requestPublish: (entities: EntityRef[]) => void;
  requestUnpublish: (entities: EntityRef[]) => void;
  pendingRequest: PublicationRequest | null;
  clearIntent: (requestId: number) => void;
}

const PublishContext = createContext<PublishContextValue | null>(null);

export function PublishProvider({ children }: { children: ReactNode }) {
  const { user } = useUser();
  const workspaceId = user?.activeWorkspace?.workspaceId;
  const [state, setState] = useState<{ workspaceId: number | undefined; request: PublicationRequest | null }>({ workspaceId, request: null });
  const sequence = useRef(0);
  // Retire an old workspace request permanently, including when returning to that workspace.
  if (state.workspaceId !== workspaceId) setState({ workspaceId, request: null });

  const request = useCallback((action: PublishIntent['action'], entities: EntityRef[]) => {
    if (workspaceId === undefined || entities.length === 0) return;
    const unique = [...new Map(entities.map(entity => [`${entity.type}:${entity.id}`, { ...entity }])).values()];
    const next = { action, entities: unique, workspaceId, requestId: ++sequence.current };
    setState(previous => previous.workspaceId !== workspaceId || previous.request ? previous : { workspaceId, request: next });
  }, [workspaceId]);
  const requestPublish = useCallback((entities: EntityRef[]) => request('publish', entities), [request]);
  const requestUnpublish = useCallback((entities: EntityRef[]) => request('unpublish', entities), [request]);
  const clearIntent = useCallback((requestId: number) => {
    setState(previous => previous.request?.requestId === requestId ? { ...previous, request: null } : previous);
  }, []);
  const value = useMemo(() => ({ requestPublish, requestUnpublish, pendingRequest: state.request, clearIntent }),
    [requestPublish, requestUnpublish, state.request, clearIntent]);
  return <PublishContext.Provider value={value}>{children}</PublishContext.Provider>;
}

export default PublishContext;
