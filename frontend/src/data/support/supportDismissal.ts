import type { SupportDismissalPort } from './ports';

const storageKey = (userId: number) => `supportBannerDismissed_${userId}`;

/** Storage restrictions must not break the app or prevent temporary dismissal. */
export const sessionSupportDismissal: SupportDismissalPort = {
  isDismissed(userId) {
    try { return sessionStorage.getItem(storageKey(userId)) === 'true'; }
    catch { return false; }
  },
  dismiss(userId) {
    try { sessionStorage.setItem(storageKey(userId), 'true'); }
    catch { /* The mounted notification still remains dismissed. */ }
  },
};
