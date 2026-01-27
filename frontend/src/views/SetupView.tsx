import { useNavigate } from 'react-router-dom';
import CollectionSetupWizard from '../CollectionSetupWizard';
import '../styles/App.css';

function SetupView() {
  const navigate = useNavigate();

  const handleComplete = (collectionId: number) => {
    navigate(`/collections/${collectionId}`);
  };

  const handleCancel = () => {
    navigate('/collections');
  };

  return (
    <CollectionSetupWizard 
      onComplete={handleComplete} 
      onCancel={handleCancel}
    />
  );
}

export default SetupView;
