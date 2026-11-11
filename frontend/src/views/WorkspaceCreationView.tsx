import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import WorkspaceSetupWizard from '../components/wizard/WorkspaceSetupWizard';
import { useUnsavedNavigation } from '../data/shared/useUnsavedNavigation';

function WorkspaceCreationView() {
  const navigate = useNavigate();
  const [status, setStatus] = useState({ dirty: false, pending: false });
  const [leaving, setLeaving] = useState(false);
  const completeNavigation = useUnsavedNavigation(!leaving && status.dirty, !leaving && status.pending);
  // The wizard has already confirmed discard. Remove unload protection before
  // leaving the SPA so cancellation does not prompt a second time.
  useEffect(() => { if (leaving) window.location.href = '/'; }, [leaving]);
  const handleComplete = () => {
    completeNavigation(() => { void navigate('/collections'); });
  };

  const handleCancel = () => {
    setLeaving(true);
  };

  return (
    <WorkspaceSetupWizard
      showTerms={false}
      isWelcome={false}
      onComplete={handleComplete}
      onCancel={handleCancel}
      onStatusChange={setStatus}
    />
  );
}

export default WorkspaceCreationView;
