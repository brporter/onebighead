import { useCallback, useState } from 'react';
import { useAsyncData } from '../../utils/useAsyncData';
import type { SupportDismissalPort, SupportNotificationPort } from './ports';

/** Mount separately for each user; reads are canceled when that session ends. */
export function useUnreadSupport(userId: number, gateway: SupportNotificationPort, storage: SupportDismissalPort) {
  const [dismissed, setDismissed] = useState(() => storage.isDismissed(userId));
  const fetch = useCallback((signal: AbortSignal) => gateway.read({ signal }), [gateway]);
  const { data } = useAsyncData(dismissed ? null : fetch);
  return {
    count: dismissed ? 0 : data?.unreadCount ?? 0,
    dismiss: () => {
      setDismissed(true);
      storage.dismiss(userId);
    },
  };
}
