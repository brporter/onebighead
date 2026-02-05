import TenantSetupWizard from '../components/wizard/TenantSetupWizard';

function TenantCreationView() {
  const handleComplete = () => {
    window.location.href = '/collections';
  };

  const handleCancel = () => {
    // If user cancels and has no tenant, log them out
    window.location.href = '/';
  };

  return (
    <TenantSetupWizard
      showTerms={false}
      isWelcome={false}
      onComplete={handleComplete}
      onCancel={handleCancel}
    />
  );
}

export default TenantCreationView;
