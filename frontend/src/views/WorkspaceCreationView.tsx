import WorkspaceSetupWizard from '../components/wizard/WorkspaceSetupWizard';

function WorkspaceCreationView() {
  const handleComplete = () => {
    window.location.href = '/collections';
  };

  const handleCancel = () => {
    // If user cancels and has no workspace, log them out
    window.location.href = '/';
  };

  return (
    <WorkspaceSetupWizard
      showTerms={false}
      isWelcome={false}
      onComplete={handleComplete}
      onCancel={handleCancel}
    />
  );
}

export default WorkspaceCreationView;
