import { useUser } from '../../contexts/useUser';
import { useNavigate } from 'react-router-dom';
import { useSignOut } from '../../data/auth/useSignOut';
import { SessionChangeFeedback } from '../common/SessionChangeFeedback';
import '../../styles/UserButton.css';

interface UserButtonProps {
  onClick?: () => void;
}

function UserButton({ onClick }: UserButtonProps) {
  const { user, loading, logout, refetch } = useUser();
  const navigate = useNavigate();
  const { changes, managed, busy, signOut, signingOut, error } = useSignOut({ logout, refetch }, () => { window.location.href = '/'; });

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
      <button className="userButton" onClick={signOut} type="button" disabled={busy}>
        {signingOut ? 'Signing out…' : 'Sign Out'}
      </button>
      {error && <p className="userButton__error" role="alert">{error}</p>}
      {!managed && <SessionChangeFeedback changes={changes} />}
    </div>
  );
}

export default UserButton;
