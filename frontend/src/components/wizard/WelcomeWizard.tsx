import { useState, useEffect } from 'react';
import { useUser } from '../../contexts/UserContext';
import { useData } from '../../contexts/DataContext';
import { authApi } from '../../api';
import type { CollectionTheme } from '../../utils/types';
import ThemeCard from '../collection/ThemeCard';
import ThemePreview from '../collection/ThemePreview';
import { TermsAcceptance } from '../common';

interface WelcomeWizardProps {
  onComplete: (collectionId: number) => void;
  onSkip: () => void;
}

type StepId = 'terms' | 'welcome' | 'theme' | 'preview';

const STEPS: { id: StepId; label: string }[] = [
  { id: 'terms', label: 'Terms' },
  { id: 'welcome', label: 'Welcome' },
  { id: 'theme', label: 'Theme' },
  { id: 'preview', label: 'Preview' },
];

function WelcomeWizard({ onComplete, onSkip }: WelcomeWizardProps) {
  const { user, refetch: refetchUser } = useUser();
  const { themes, themesLoading, loadThemes, setupCollection } = useData();

  // Start at terms step if user hasn't accepted terms, otherwise skip to welcome
  const [activeStep, setActiveStep] = useState<StepId>(() =>
    user?.hasAcceptedTerms ? 'welcome' : 'terms'
  );
  const [termsAccepted, setTermsAccepted] = useState(user?.hasAcceptedTerms ?? false);
  const [tenantName, setTenantName] = useState('');
  const [collectionName, setCollectionName] = useState('');
  const [collectionDescription, setCollectionDescription] = useState('');
  const [selectedThemeId, setSelectedThemeId] = useState<number | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadThemes();
  }, [loadThemes]);

  // Pre-fill tenant name with email
  useEffect(() => {
    if (user?.email && !tenantName) {
      setTenantName(user.email);
    }
  }, [user?.email, tenantName]);

  // Auto-select General theme as default
  useEffect(() => {
    if (themes.length > 0 && selectedThemeId === null) {
      const generalTheme = themes.find(t => t.name === 'General');
      if (generalTheme) {
        setSelectedThemeId(generalTheme.themeId);
      }
    }
  }, [themes, selectedThemeId]);

  const selectedTheme: CollectionTheme | null = selectedThemeId
    ? themes.find(t => t.themeId === selectedThemeId) ?? null
    : null;

  const handleTermsAccepted = async () => {
    setTermsAccepted(true);
    await refetchUser();
    setActiveStep('welcome');
  };

  const canProceed = (step: StepId): boolean => {
    switch (step) {
      case 'terms':
        return termsAccepted;
      case 'welcome':
        return tenantName.trim().length > 0 && collectionName.trim().length > 0;
      case 'theme':
        return selectedThemeId !== null;
      case 'preview':
        return true;
      default:
        return false;
    }
  };

  const currentStepIndex = STEPS.findIndex(s => s.id === activeStep);

  const handleNext = () => {
    if (currentStepIndex < STEPS.length - 1) {
      setActiveStep(STEPS[currentStepIndex + 1].id);
    }
  };

  const handlePrevious = () => {
    if (currentStepIndex > 0) {
      setActiveStep(STEPS[currentStepIndex - 1].id);
    }
  };

  const handleSkip = async () => {
    setIsSubmitting(true);
    setError(null);

    try {
      // Complete welcome without a tenant name (backend will use email)
      await authApi.completeWelcome(undefined);
      await refetchUser();
      onSkip();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to complete setup');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSubmit = async () => {
    if (!selectedThemeId) {
      setError('Please select a theme');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      // First complete the welcome with tenant name
      await authApi.completeWelcome(tenantName.trim());
      await refetchUser();

      // Then create the collection
      const collection = await setupCollection({
        name: collectionName.trim(),
        description: collectionDescription.trim(),
        themeId: selectedThemeId,
      });

      onComplete(collection.collectionId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to complete setup');
    } finally {
      setIsSubmitting(false);
    }
  };

  const renderStepContent = () => {
    switch (activeStep) {
      case 'terms':
        return (
          <div className="setupWizard__content setupWizard__content--terms">
            <TermsAcceptance onAccepted={handleTermsAccepted} />
          </div>
        );

      case 'welcome':
        return (
          <div className="setupWizard__content">
            <div className="welcomeWizard__intro">
              <h2 className="welcomeWizard__greeting">Welcome to OneBigHead!</h2>
              <p className="welcomeWizard__description">
                Let's get you set up. First, tell us a bit about yourself and your first collection.
              </p>
            </div>

            <div className="setupWizard__field">
              <label htmlFor="tenant-name" className="setupWizard__label">
                Organization / Workspace Name <span className="setupWizard__required">*</span>
              </label>
              <input
                id="tenant-name"
                type="text"
                className="setupWizard__input"
                value={tenantName}
                onChange={(e) => setTenantName(e.target.value)}
                placeholder="Your name, company, or workspace"
                autoFocus
              />
              <p className="setupWizard__hint">
                This is how your workspace will be identified.
              </p>
            </div>

            <div className="setupWizard__field">
              <label htmlFor="collection-name" className="setupWizard__label">
                First Collection Name <span className="setupWizard__required">*</span>
              </label>
              <input
                id="collection-name"
                type="text"
                className="setupWizard__input"
                value={collectionName}
                onChange={(e) => setCollectionName(e.target.value)}
                placeholder="e.g., My Book Collection"
              />
            </div>

            <div className="setupWizard__field">
              <label htmlFor="collection-description" className="setupWizard__label">
                Description
              </label>
              <textarea
                id="collection-description"
                className="setupWizard__textarea"
                value={collectionDescription}
                onChange={(e) => setCollectionDescription(e.target.value)}
                placeholder="What will you be collecting?"
                rows={3}
              />
            </div>
          </div>
        );

      case 'theme':
        return (
          <div className="setupWizard__content">
            <p className="setupWizard__hint">
              Choose a theme to get started with pre-configured templates and categories.
              You can always customize these later.
            </p>
            {themesLoading ? (
              <p className="setupWizard__loading">Loading themes...</p>
            ) : (
              <div className="setupWizard__themeGrid">
                {themes.map((theme) => (
                  <ThemeCard
                    key={theme.themeId}
                    theme={theme}
                    isSelected={selectedThemeId === theme.themeId}
                    onSelect={() => setSelectedThemeId(theme.themeId)}
                  />
                ))}
              </div>
            )}
          </div>
        );

      case 'preview':
        return (
          <div className="setupWizard__content">
            {selectedTheme ? (
              <>
                <div className="setupWizard__summary">
                  <h3 className="setupWizard__summaryTitle">Setup Summary</h3>
                  <dl className="setupWizard__summaryList">
                    <dt>Workspace Name</dt>
                    <dd>{tenantName}</dd>
                    <dt>Collection Name</dt>
                    <dd>{collectionName}</dd>
                    {collectionDescription && (
                      <>
                        <dt>Description</dt>
                        <dd>{collectionDescription}</dd>
                      </>
                    )}
                    <dt>Theme</dt>
                    <dd>{selectedTheme.name}</dd>
                  </dl>
                </div>
                <ThemePreview theme={selectedTheme} />
              </>
            ) : (
              <p className="setupWizard__hint">Please select a theme to see the preview.</p>
            )}
          </div>
        );
    }
  };

  return (
    <div className="setupWizard">
      <div className="setupWizard__container">
        <div className="setupWizard__header">
          <h1 className="setupWizard__title">Get Started</h1>
          <div className="setupWizard__headerActions">
            {/* Hide skip button on terms step - terms must be accepted */}
            {activeStep !== 'terms' && (
              <button
                className="setupWizard__skipBtn"
                onClick={handleSkip}
                disabled={isSubmitting}
              >
                Skip Setup
              </button>
            )}
          </div>
        </div>

        <nav className="setupWizard__tabs">
          {STEPS.map((step, index) => (
            <button
              key={step.id}
              className={`setupWizard__tab ${activeStep === step.id ? 'setupWizard__tab--active' : ''}`}
              onClick={() => setActiveStep(step.id)}
              disabled={index > 0 && !canProceed(STEPS[index - 1].id)}
            >
              <span className="setupWizard__tabNumber">{index + 1}</span>
              {step.label}
            </button>
          ))}
        </nav>

        {error && (
          <div className="setupWizard__error" role="alert">
            {error}
          </div>
        )}

        {renderStepContent()}

        {/* Hide navigation footer on terms step - TermsAcceptance has its own button */}
        {activeStep !== 'terms' && (
          <div className="setupWizard__footer">
            <button
              className="setupWizard__btn setupWizard__btn--secondary"
              onClick={handlePrevious}
              disabled={currentStepIndex === 0 || activeStep === 'welcome' || isSubmitting}
            >
              Previous
            </button>

            {activeStep === 'preview' ? (
              <button
                className="setupWizard__btn setupWizard__btn--primary"
                onClick={handleSubmit}
                disabled={!canProceed('welcome') || !canProceed('theme') || isSubmitting}
              >
                {isSubmitting ? 'Creating...' : 'Get Started'}
              </button>
            ) : (
              <button
                className="setupWizard__btn setupWizard__btn--primary"
                onClick={handleNext}
                disabled={!canProceed(activeStep)}
              >
                Next
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default WelcomeWizard;
