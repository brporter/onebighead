import { createContext, useState, useCallback, type ReactNode } from 'react';
import type { EntityRef, PublishIntent } from '../utils/types';

export interface PublishContextValue {
  requestPublish: (entities: EntityRef[]) => void;
  requestUnpublish: (entities: EntityRef[]) => void;
  pendingIntent: PublishIntent | null;
  clearIntent: () => void;
}

const PublishContext = createContext<PublishContextValue>({
  requestPublish: () => {},
  requestUnpublish: () => {},
  pendingIntent: null,
  clearIntent: () => {},
});

export function PublishProvider({ children }: { children: ReactNode }) {
  const [pendingIntent, setPendingIntent] = useState<PublishIntent | null>(null);

  const requestPublish = useCallback((entities: EntityRef[]) => {
    setPendingIntent({ action: 'publish', entities });
  }, []);

  const requestUnpublish = useCallback((entities: EntityRef[]) => {
    setPendingIntent({ action: 'unpublish', entities });
  }, []);

  const clearIntent = useCallback(() => {
    setPendingIntent(null);
  }, []);

  return (
    <PublishContext.Provider value={{ requestPublish, requestUnpublish, pendingIntent, clearIntent }}>
      {children}
    </PublishContext.Provider>
  );
}

export default PublishContext;
