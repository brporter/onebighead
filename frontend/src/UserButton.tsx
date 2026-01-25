import { useUser } from './UserContext';
import { useNavigate } from 'react-router-dom';
import './styles/UserButton.css';

interface UserButtonProps {
  onClick: () => void;
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
      <button className="userButton" onClick={onClick} type="button">
        {user.email}
      </button>
      <button className="userButton userButton--signout" onClick={handleSignOut} type="button">
        Sign Out
      </button>
    </div>
  );
}

export default UserButton;
