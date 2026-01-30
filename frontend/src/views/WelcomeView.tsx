import { useNavigate } from 'react-router-dom';
import WelcomeWizard from '../components/wizard/WelcomeWizard';
import '../styles/App.css';
import '../styles/WelcomeWizard.css';

function WelcomeView() {
  const navigate = useNavigate();

  const handleComplete = (collectionId: number) => {
    navigate(`/collections/${collectionId}`);
  };

  const handleSkip = () => {
    navigate('/collections');
  };

  return (
    <WelcomeWizard onComplete={handleComplete} onSkip={handleSkip} />
  );
}

export default WelcomeView;
