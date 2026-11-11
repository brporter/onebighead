import { useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { useUser } from '../contexts/useUser';
import WelcomeWizard from '../components/wizard/WelcomeWizard';
import { useUnsavedNavigation } from '../data/shared/useUnsavedNavigation';
import '../styles/App.css';

function WelcomeView() {
  const { user } = useUser();
  if (!user?.isWorkspaceAdmin) return <Navigate to="/collections" replace />;
  return <WelcomeSession key={`${user.userId}:${user.workspaceId}`} />;
}

function WelcomeSession() {
  const navigate = useNavigate();
  const [status, setStatus] = useState({ dirty: false, pending: false });
  const completeNavigation = useUnsavedNavigation(status.dirty, status.pending);

  const handleComplete = (collectionId: number | null) => {
    completeNavigation(() => { void navigate(collectionId === null ? '/collections' : `/collections/${collectionId}`); });
  };

  const handleSkip = () => {
    completeNavigation(() => { void navigate('/collections'); });
  };

  return (
    <WelcomeWizard onComplete={handleComplete} onSkip={handleSkip} onStatusChange={setStatus} />
  );
}

export default WelcomeView;
