import { useContext } from 'react';
import PublishContext from './PublishContext';
import type { PublishContextValue } from './PublishContext';

export function usePublish(): PublishContextValue {
  return useContext(PublishContext);
}
