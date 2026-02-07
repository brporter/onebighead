import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '../../contexts/UserContext';
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

  // Initialize isDismissed from sessionStorage if we have a user
  const [isDismissed, setIsDismissed] = useState(() => {
    if (typeof window === 'undefined') return false;
    // Note: user may not be available during initial render, will be checked in effect
    return false;
  });

  useEffect(() => {
    if (!user) return;

    // Check if we've already shown the banner this session for this user
    const storageKey = getStorageKey(user.userId);
    const dismissed = sessionStorage.getItem(storageKey);
    if (dismissed === 'true') {
      // Already dismissed, skip fetch
      setIsDismissed(true);
      return;
    }

    // Fetch unread count
    getUnreadSupportCount()
      .then((data) => setUnreadCount(data.unreadCount))
      .catch(() => setUnreadCount(0));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.userId]);

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
