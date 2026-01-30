import { useState, useEffect } from 'react';
import { useData } from '../../contexts/DataContext';
import type { CollectionTheme } from '../../utils/types';
import ThemeCard from './ThemeCard';
import ThemePreview from './ThemePreview';

interface CollectionSetupWizardProps {
  onComplete: (collectionId: number) => void;
  onCancel?: () => void;
  isModal?: boolean;
}

type TabId = 'basics' | 'theme' | 'preview';

const TABS: { id: TabId; label: string }[] = [
  { id: 'basics', label: 'Basics' },
  { id: 'theme', label: 'Theme' },
  { id: 'preview', label: 'Preview' },
];

function CollectionSetupWizard({ onComplete, onCancel, isModal = false }: CollectionSetupWizardProps) {
  const { themes, themesLoading, loadThemes, setupCollection } = useData();
  
  const [activeTab, setActiveTab] = useState<TabId>('basics');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [selectedThemeId, setSelectedThemeId] = useState<number | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadThemes();
  }, [loadThemes]);

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

  const canProceed = (tab: TabId): boolean => {
    switch (tab) {
      case 'basics':
        return name.trim().length > 0;
      case 'theme':
        return selectedThemeId !== null;
      case 'preview':
        return true;
      default:
        return false;
    }
  };

  const currentTabIndex = TABS.findIndex(t => t.id === activeTab);

  const handleNext = () => {
    if (currentTabIndex < TABS.length - 1) {
      setActiveTab(TABS[currentTabIndex + 1].id);
    }
  };

  const handlePrevious = () => {
    if (currentTabIndex > 0) {
      setActiveTab(TABS[currentTabIndex - 1].id);
    }
  };

  const handleSkip = async () => {
    // Find General theme and use it
    const generalTheme = themes.find(t => t.name === 'General');
    if (!generalTheme) {
      setError('Unable to find default theme');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      const collection = await setupCollection({
        name: name.trim() || 'My Collection',
        description: description.trim() || '',
        themeId: generalTheme.themeId,
      });
      onComplete(collection.collectionId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create collection');
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
      const collection = await setupCollection({
        name: name.trim(),
        description: description.trim(),
        themeId: selectedThemeId,
      });
      onComplete(collection.collectionId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create collection');
    } finally {
      setIsSubmitting(false);
    }
  };

  const renderTabContent = () => {
    switch (activeTab) {
      case 'basics':
        return (
          <div className="setupWizard__content">
            <div className="setupWizard__field">
              <label htmlFor="collection-name" className="setupWizard__label">
                Collection Name <span className="setupWizard__required">*</span>
              </label>
              <input
                id="collection-name"
                type="text"
                className="setupWizard__input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., My Book Collection"
                autoFocus
              />
            </div>
            <div className="setupWizard__field">
              <label htmlFor="collection-description" className="setupWizard__label">
                Description
              </label>
              <textarea
                id="collection-description"
                className="setupWizard__textarea"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
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
                  <h3 className="setupWizard__summaryTitle">Collection Summary</h3>
                  <dl className="setupWizard__summaryList">
                    <dt>Name</dt>
                    <dd>{name}</dd>
                    {description && (
                      <>
                        <dt>Description</dt>
                        <dd>{description}</dd>
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
    <div className={`setupWizard ${isModal ? 'setupWizard--modal' : ''}`}>
      <div className="setupWizard__container">
        <div className="setupWizard__header">
          <h1 className="setupWizard__title">{isModal ? 'New Collection' : 'Create Your Collection'}</h1>
          <div className="setupWizard__headerActions">
            {onCancel && (
              <button
                className="setupWizard__cancelBtn"
                onClick={onCancel}
                disabled={isSubmitting}
              >
                Cancel
              </button>
            )}
            {!isModal && (
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
          {TABS.map((tab, index) => (
            <button
              key={tab.id}
              className={`setupWizard__tab ${activeTab === tab.id ? 'setupWizard__tab--active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
              disabled={index > 0 && !canProceed(TABS[index - 1].id)}
            >
              <span className="setupWizard__tabNumber">{index + 1}</span>
              {tab.label}
            </button>
          ))}
        </nav>

        {error && (
          <div className="setupWizard__error" role="alert">
            {error}
          </div>
        )}

        {renderTabContent()}

        <div className="setupWizard__footer">
          <button
            className="setupWizard__btn setupWizard__btn--secondary"
            onClick={handlePrevious}
            disabled={currentTabIndex === 0 || isSubmitting}
          >
            Previous
          </button>
          
          {activeTab === 'preview' ? (
            <button
              className="setupWizard__btn setupWizard__btn--primary"
              onClick={handleSubmit}
              disabled={!canProceed('basics') || !canProceed('theme') || isSubmitting}
            >
              {isSubmitting ? 'Creating...' : 'Create Collection'}
            </button>
          ) : (
            <button
              className="setupWizard__btn setupWizard__btn--primary"
              onClick={handleNext}
              disabled={!canProceed(activeTab)}
            >
              Next
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export default CollectionSetupWizard;
