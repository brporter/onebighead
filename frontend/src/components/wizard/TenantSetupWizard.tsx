import { useState, useEffect, useRef } from 'react';
import { useUser } from '../../contexts/UserContext';
import { useData } from '../../contexts/DataContext';
import { authApi, tenantsApi } from '../../api';
import type { CollectionTheme, SetupCollectionRequest } from '../../utils/types';
import ThemeCard from '../collection/ThemeCard';
import ThemePreview from '../collection/ThemePreview';
import { TermsAcceptance } from '../common';

export interface TenantSetupResult {
  tenantId: number;
  tenantName: string;
  collectionId: number;
  collectionName: string;
}

interface TenantSetupWizardProps {
  /** Whether to show the terms acceptance step */
  showTerms?: boolean;
  /** Whether this is the initial welcome wizard (vs creating additional tenant) */
  isWelcome?: boolean;
  /** Called when setup is complete */
  onComplete: (result: TenantSetupResult) => void;
  /** Called when user cancels (only shown if not isWelcome) */
  onCancel?: () => void;
  /** Called when user skips setup (only for welcome wizard) */
  onSkip?: () => void;
}

type StepId = 'terms' | 'details' | 'theme' | 'preview';

function TenantSetupWizard({
  showTerms = false,
  isWelcome = false,
  onComplete,
  onCancel,
  onSkip,
}: TenantSetupWizardProps) {
  const { user, refetch: refetchUser } = useUser();
  const { themes, themesLoading, loadThemes, setupCollection } = useData();

  // Determine initial step
  const getInitialStep = (): StepId => {
    if (showTerms && !user?.hasAcceptedTerms) {
      return 'terms';
    }
    return 'details';
  };

  const [activeStep, setActiveStep] = useState<StepId>(getInitialStep);
  const [termsAccepted, setTermsAccepted] = useState(user?.hasAcceptedTerms ?? false);
  const [tenantName, setTenantName] = useState('');
  const hasPrefilledTenantName = useRef(false);
  const [collectionName, setCollectionName] = useState('');
  const [collectionDescription, setCollectionDescription] = useState('');
  const [selectedThemeId, setSelectedThemeId] = useState<number | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Build steps array based on whether terms should be shown
  const steps: { id: StepId; label: string }[] = [];
  if (showTerms) {
    steps.push({ id: 'terms', label: 'Terms' });
  }
  steps.push(
    { id: 'details', label: isWelcome ? 'Welcome' : 'Details' },
    { id: 'theme', label: 'Theme' },
    { id: 'preview', label: 'Preview' }
  );

  useEffect(() => {
    loadThemes();
  }, [loadThemes]);

  // Pre-fill tenant name with email for welcome wizard (only once)
  useEffect(() => {
    if (isWelcome && user?.email && !hasPrefilledTenantName.current) {
      hasPrefilledTenantName.current = true;
      setTenantName(user.email);
    }
  }, [isWelcome, user?.email]);

  // Auto-select General theme as default
  useEffect(() => {
    if (themes.length > 0 && selectedThemeId === null) {
      const generalTheme = themes.find((t) => t.name === 'General');
      if (generalTheme) {
        setSelectedThemeId(generalTheme.themeId);
      }
    }
  }, [themes, selectedThemeId]);

  const selectedTheme: CollectionTheme | null = selectedThemeId
    ? themes.find((t) => t.themeId === selectedThemeId) ?? null
    : null;

  const handleTermsAccepted = async () => {
    setTermsAccepted(true);
    await refetchUser();
    setActiveStep('details');
  };

  const canProceed = (step: StepId): boolean => {
    switch (step) {
      case 'terms':
        return termsAccepted;
      case 'details':
        return tenantName.trim().length > 0;
      case 'theme':
        return selectedThemeId !== null;
      case 'preview':
        return true;
      default:
        return false;
    }
  };

  const currentStepIndex = steps.findIndex((s) => s.id === activeStep);

  const handleNext = () => {
    if (currentStepIndex < steps.length - 1) {
      setActiveStep(steps[currentStepIndex + 1].id);
    }
  };

  const handlePrevious = () => {
    if (currentStepIndex > 0) {
      // Don't go back to terms if already accepted
      const prevStep = steps[currentStepIndex - 1];
      if (prevStep.id === 'terms' && termsAccepted) {
        return;
      }
      setActiveStep(prevStep.id);
    }
  };

  const handleSkip = async () => {
    if (!isWelcome || !onSkip) return;

    setIsSubmitting(true);
    setError(null);

    try {
      // Complete welcome without full setup
      await authApi.completeWelcome(tenantName.trim() || undefined);
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
      if (isWelcome) {
        // For welcome wizard: complete welcome then create collection
        await authApi.completeWelcome(tenantName.trim());

        const collection = await setupCollection({
          name: collectionName.trim() || 'My Collection',
          description: collectionDescription.trim(),
          themeId: selectedThemeId,
        });

        await refetchUser();

        onComplete({
          tenantId: user?.tenantId ?? 0,
          tenantName: tenantName.trim(),
          collectionId: collection.collectionId,
          collectionName: collection.name,
        });
      } else {
        // For settings: use the new setup endpoint
        const result = await tenantsApi.setup({
          tenantName: tenantName.trim(),
          collectionName: collectionName.trim() || undefined,
          collectionDescription: collectionDescription.trim() || undefined,
          themeId: selectedThemeId,
        });

        await refetchUser();

        onComplete({
          tenantId: result.tenantId,
          tenantName: result.tenantName,
          collectionId: result.collectionId,
          collectionName: result.collectionName,
        });
      }
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

      case 'details':
        return (
          <div className="setupWizard__content">
            {isWelcome && (
              <div className="welcomeWizard__intro">
                <h2 className="welcomeWizard__greeting">Welcome to OneBigHead!</h2>
                <p className="welcomeWizard__description">
                  Let's get you set up. First, tell us a bit about yourself and your first
                  collection.
                </p>
              </div>
            )}

            <div className="setupWizard__field">
              <label htmlFor="tenant-name" className="setupWizard__label">
                {isWelcome ? 'Organization / Workspace Name' : 'New Workspace Name'}{' '}
                <span className="setupWizard__required">*</span>
              </label>
              <input
                id="tenant-name"
                type="text"
                className="setupWizard__input"
                value={tenantName}
                onChange={(e) => setTenantName(e.target.value)}
                placeholder={isWelcome ? 'Your name, company, or workspace' : 'Enter workspace name'}
                autoFocus
              />
              <p className="setupWizard__hint">This is how your workspace will be identified.</p>
            </div>

            <div className="setupWizard__field">
              <label htmlFor="collection-name" className="setupWizard__label">
                {isWelcome ? 'First Collection Name' : 'Collection Name'}
              </label>
              <input
                id="collection-name"
                type="text"
                className="setupWizard__input"
                value={collectionName}
                onChange={(e) => setCollectionName(e.target.value)}
                placeholder="e.g., My Book Collection (defaults to 'My Collection')"
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
              Choose a theme to get started with pre-configured templates and categories. You can
              always customize these later.
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
                    <dd>{collectionName || 'My Collection'}</dd>
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

  const showSkipButton = isWelcome && onSkip && activeStep !== 'terms';
  const showCancelButton = !isWelcome && onCancel;

  return (
    <div className={`setupWizard ${!isWelcome ? 'setupWizard--modal' : ''}`}>
      <div className="setupWizard__container">
        <div className="setupWizard__header">
          <h1 className="setupWizard__title">
            {isWelcome ? 'Get Started' : 'Create New Workspace'}
          </h1>
          <div className="setupWizard__headerActions">
            {showCancelButton && (
              <button
                className="setupWizard__cancelBtn"
                onClick={onCancel}
                disabled={isSubmitting}
              >
                Cancel
              </button>
            )}
            {showSkipButton && (
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
          {steps.map((step, index) => (
            <button
              key={step.id}
              className={`setupWizard__tab ${activeStep === step.id ? 'setupWizard__tab--active' : ''}`}
              onClick={() => {
                // Allow clicking only if previous steps are complete
                if (index === 0 || canProceed(steps[index - 1].id)) {
                  // Don't allow going back to terms if already accepted
                  if (step.id === 'terms' && termsAccepted) return;
                  setActiveStep(step.id);
                }
              }}
              disabled={index > 0 && !canProceed(steps[index - 1].id)}
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
              disabled={
                currentStepIndex === 0 ||
                (steps[currentStepIndex - 1]?.id === 'terms' && termsAccepted) ||
                isSubmitting
              }
            >
              Previous
            </button>

            {activeStep === 'preview' ? (
              <button
                className="setupWizard__btn setupWizard__btn--primary"
                onClick={handleSubmit}
                disabled={!canProceed('details') || !canProceed('theme') || isSubmitting}
              >
                {isSubmitting ? 'Creating...' : isWelcome ? 'Get Started' : 'Create Workspace'}
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

export default TenantSetupWizard;
