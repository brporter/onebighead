import { useContext } from 'react';
import PublishContext from './PublishContext';
import type { PublishContextValue } from './PublishContext';

export function usePublish(): PublishContextValue {
  const ctx = useContext(PublishContext);
  if (!ctx) throw new Error('usePublish must be used within a PublishProvider');
  return ctx;
}
