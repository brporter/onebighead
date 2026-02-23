import { useUser } from '../../contexts/useUser';
import { useNavigate } from 'react-router-dom';
import '../../styles/UserButton.css';

interface UserButtonProps {
  onClick?: () => void;
}

function UserButton({ onClick }: UserButtonProps) {
  const { user, loading, logout } = useUser();
  const navigate = useNavigate();

  if (loading || !user) {
    return null;
  }

  const handleAdminClick = () => {
    navigate('/admin');
  };

  const handleSettingsClick = () => {
    if (onClick) {
      onClick();
    } else {
      navigate('/settings');
    }
  };

  const handleSignOut = async () => {
    await logout();
    window.location.href = '/';
  };

  return (
    <div className="userButton__container">
      {user.isSystemAdministrator && (
        <button className="userButton userButton--admin" onClick={handleAdminClick} type="button">
          Admin
        </button>
      )}
      <button className="userButton userButton--icon" onClick={handleSettingsClick} type="button" title="Settings" aria-label="Settings">
        <span className="userButton__icon">⚙</span>
      </button>
      <button className="userButton" onClick={handleSignOut} type="button">
        Sign Out
      </button>
    </div>
  );
}

export default UserButton;
