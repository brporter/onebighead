import { useNavigate } from 'react-router-dom';
import { useUser } from '../contexts/UserContext';
import { TermsAcceptance } from '../components/common/TermsAcceptance';
import '../styles/TermsAcceptance.css';

function TermsView() {
  const navigate = useNavigate();
  const { refetch, logout } = useUser();

  const handleAccepted = async () => {
    // Refresh user data to get updated hasAcceptedTerms
    await refetch();
    // Navigate to collections (or welcome if needed)
    navigate('/collections', { replace: true });
  };

  const handleSignOut = async () => {
    await logout();
    window.location.href = '/';
  };

  return (
    <div className="terms-view">
      <header className="terms-view__header">
        <div className="terms-view__header-content">
          <span className="terms-view__logo">OneBigHead</span>
        </div>
      </header>

      <main className="terms-view__main">
        <div className="terms-view__container">
          <TermsAcceptance
            onAccepted={handleAccepted}
            showSkip={true}
            onSkip={handleSignOut}
          />
        </div>
      </main>
    </div>
  );
}

export default TermsView;
