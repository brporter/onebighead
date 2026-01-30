import { useNavigate } from 'react-router-dom';
import CollectionSetupWizard from '../components/collection/CollectionSetupWizard';
import '../styles/App.css';

function SetupView() {
  const navigate = useNavigate();

  const handleComplete = (collectionId: number) => {
    navigate(`/collections/${collectionId}`);
  };

  return (
    <CollectionSetupWizard onComplete={handleComplete} />
  );
}

export default SetupView;
