import { useUser } from './UserContext';
import './styles/UserButton.css';

interface UserButtonProps {
  onClick: () => void;
}

function UserButton({ onClick }: UserButtonProps) {
  const { user, loading } = useUser();

  if (loading || !user) {
    return null;
  }

  return (
    <button className="userButton" onClick={onClick} type="button">
      {user.email}
    </button>
  );
}

export default UserButton;
