import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '../../contexts/useUser';
import { getUnreadSupportCount } from '../../api';
import '../../styles/Support.css';

interface UnreadSupportBannerProps {
  onOpenSettings?: () => void;
}

// Namespace sessionStorage key by user id to prevent cross-user issues
function getStorageKey(userId: number) {
  return `supportBannerDismissed_${userId}`;
}

export function UnreadSupportBanner({ onOpenSettings }: UnreadSupportBannerProps) {
  const { user } = useUser();
  const navigate = useNavigate();
  const [unreadCount, setUnreadCount] = useState(0);

  const userId = user?.userId;

  // Initialize isDismissed from sessionStorage
  const [isDismissed, setIsDismissed] = useState(() => {
    if (typeof window === 'undefined' || !userId) return false;
    return sessionStorage.getItem(getStorageKey(userId)) === 'true';
  });

  useEffect(() => {
    if (!userId) return;

    // Check if already dismissed in sessionStorage (covers case where userId
    // wasn't available during initial render)
    if (sessionStorage.getItem(getStorageKey(userId)) === 'true') {
      // Already dismissed — schedule state update as a microtask
      void Promise.resolve().then(() => setIsDismissed(true));
      return;
    }

    // Fetch unread count
    getUnreadSupportCount()
      .then((data) => setUnreadCount(data.unreadCount))
      .catch(() => setUnreadCount(0));
  }, [userId]);

  if (!user || unreadCount === 0 || isDismissed) {
    return null;
  }

  const handleDismiss = () => {
    setIsDismissed(true);
    if (user) {
      sessionStorage.setItem(getStorageKey(user.userId), 'true');
    }
  };

  const handleViewSupport = () => {
    handleDismiss();
    if (onOpenSettings) {
      onOpenSettings();
    } else {
      navigate('/settings?section=support');
    }
  };

  return (
    <div className="support-banner">
      <span className="support-banner__message">
        You have {unreadCount} unread support {unreadCount === 1 ? 'reply' : 'replies'}.
      </span>
      <button className="support-banner__link" onClick={handleViewSupport}>
        View in Settings
      </button>
      <button
        className="support-banner__close"
        onClick={handleDismiss}
        aria-label="Dismiss"
      >
        ×
      </button>
    </div>
  );
}
