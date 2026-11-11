import WorkspaceSetupWizard from './WorkspaceSetupWizard';
import type { EditorStatusListener } from '../../data/shared/useEditorStatus';

interface WelcomeWizardProps {
  onComplete: (collectionId: number | null) => void;
  onSkip: () => void;
  onStatusChange?: EditorStatusListener;
}

function WelcomeWizard({ onComplete, onSkip, onStatusChange }: WelcomeWizardProps) {
  return <WorkspaceSetupWizard showTerms isWelcome onComplete={result => onComplete(result.collectionId)} onSkip={onSkip} onStatusChange={onStatusChange} />;
}

export default WelcomeWizard;
