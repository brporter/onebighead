import { useNavigate } from 'react-router-dom';
import { useUser } from '../../contexts/useUser';
import { getUnreadSupportCount } from '../../api';
import type { SupportNotificationPort } from '../../data/support/ports';
import { sessionSupportDismissal } from '../../data/support/supportDismissal';
import { useUnreadSupport } from '../../data/support/useUnreadSupport';
import '../../styles/components/UnreadSupportBanner.css';

interface UnreadSupportBannerProps { onOpenSettings?: () => void }
const gateway: SupportNotificationPort = { read: getUnreadSupportCount };

export function UnreadSupportBanner({ onOpenSettings }: UnreadSupportBannerProps) {
  const { user } = useUser();
  const navigate = useNavigate();
  if (!user) return null;
  return <SupportNotification key={user.userId} userId={user.userId}
    onOpenSettings={onOpenSettings ?? (() => navigate('/settings?section=support'))} />;
}

function SupportNotification({ userId, onOpenSettings }: { userId: number; onOpenSettings: () => void }) {
  const notification = useUnreadSupport(userId, gateway, sessionSupportDismissal);
  if (notification.count <= 0) return null;
  return <aside className="support-banner" aria-label="Support replies">
    <span className="support-banner__message" role="status">
      You have {notification.count} unread support {notification.count === 1 ? 'reply' : 'replies'}.
    </span>
    <button type="button" className="support-banner__link" onClick={() => { notification.dismiss(); onOpenSettings(); }}>
      View in Settings
    </button>
    <button type="button" className="support-banner__close" onClick={notification.dismiss} aria-label="Dismiss support notification">×</button>
  </aside>;
}
