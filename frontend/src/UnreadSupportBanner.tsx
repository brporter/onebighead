import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from './UserContext';
import { getUnreadSupportCount } from './api';
import './styles/Support.css';

interface UnreadSupportBannerProps {
  onOpenSettings?: () => void;
}

export function UnreadSupportBanner({ onOpenSettings }: UnreadSupportBannerProps) {
  const { user } = useUser();
  const navigate = useNavigate();
  const [unreadCount, setUnreadCount] = useState(0);
  const [isDismissed, setIsDismissed] = useState(false);

  // Namespace sessionStorage key by user id to prevent cross-user issues
  const getStorageKey = () => user ? `supportBannerDismissed_${user.userId}` : null;

  useEffect(() => {
    if (!user) return;

    // Check if we've already shown the banner this session for this user
    const storageKey = getStorageKey();
    if (storageKey) {
      const dismissed = sessionStorage.getItem(storageKey);
      if (dismissed === 'true') {
        setIsDismissed(true);
        return;
      }
    }

    // Fetch unread count
    getUnreadSupportCount()
      .then((data) => setUnreadCount(data.unreadCount))
      .catch(() => setUnreadCount(0));
  }, [user]);

  if (!user || unreadCount === 0 || isDismissed) {
    return null;
  }

  const handleDismiss = () => {
    setIsDismissed(true);
    const storageKey = getStorageKey();
    if (storageKey) {
      sessionStorage.setItem(storageKey, 'true');
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
