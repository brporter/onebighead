import { useEffect, useId, useState } from 'react';
import { useThemesData, useCollectionsData } from '../../contexts/useData';
import { useCollectionSetup } from '../../data/collections/useCollectionSetup';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import { ContentState } from '../common/ContentState';
import { SetupThemePicker } from './SetupThemePicker';
import ThemePreview from './ThemePreview';
import '../../styles/components/CollectionSetupWizard.css';

interface CollectionSetupWizardProps {
  onComplete: (collectionId: number) => void;
  onCancel?: () => void;
  isModal?: boolean;
  onStatusChange?: EditorStatusListener;
}

const tabs = ['Basics', 'Theme', 'Preview'] as const;
type Tab = typeof tabs[number];

function CollectionSetupWizard({ onComplete, onCancel, isModal = false, onStatusChange }: CollectionSetupWizardProps) {
  const { themes, themesLoading, themesError, loadThemes } = useThemesData();
  const { setupCollection } = useCollectionsData();
  const editor = useCollectionSetup(themes, setupCollection, onComplete);
  const [tab, setTab] = useState<Tab>('Basics');
  const id = useId();
  useEditorStatus(editor.dirty, editor.pending, onStatusChange);
  useEffect(() => { void loadThemes(); }, [loadThemes]);
  const canOpen = { Basics: true, Theme: !!editor.name.trim(), Preview: !!editor.name.trim() && !!editor.selectedTheme };
  const Heading = isModal ? 'h2' : 'h1';

  return <section className={`collection-setup setupWizard${isModal ? ' setupWizard--modal' : ''}`} aria-labelledby={`${id}-title`}>
    <div className="setupWizard__container">
      <div className="setupWizard__header">
        <Heading id={`${id}-title`} className="setupWizard__title">{isModal ? 'New Collection' : 'Create Your Collection'}</Heading>
        <div className="setupWizard__headerActions">
          {onCancel && <button type="button" className="setupWizard__cancelBtn" disabled={editor.pending} onClick={() => {
            if (!editor.dirty || window.confirm('You have unsaved changes. Discard them?')) onCancel();
          }}>Cancel</button>}
          {!isModal && <button type="button" className="setupWizard__skipBtn" disabled={editor.pending} onClick={() => void editor.create(true)}>Skip Setup</button>}
        </div>
      </div>
      <fieldset className="collection-setup__fields" disabled={editor.pending} aria-busy={editor.pending}>
        <nav className="setupWizard__tabs" aria-label="Collection setup steps">
          {tabs.map((step, index) => <button type="button" key={step} className={`setupWizard__tab${tab === step ? ' setupWizard__tab--active' : ''}`}
            aria-current={tab === step ? 'step' : undefined} onClick={() => setTab(step)} disabled={!canOpen[step]}>
            <span className="setupWizard__tabNumber" aria-hidden="true">{index + 1}</span>{step}
          </button>)}
        </nav>
        {editor.error && <ContentState kind="error" title="Unable to create collection">{editor.error}</ContentState>}
        <div className="setupWizard__content">
          {tab === 'Basics' && <>
            <div className="setupWizard__field">
              <label htmlFor={`${id}-name`} className="setupWizard__label">Collection Name <span aria-hidden="true">*</span></label>
              <input id={`${id}-name`} className="setupWizard__input" value={editor.name} aria-required="true" autoFocus
                placeholder="e.g., My Book Collection" onChange={event => editor.setName(event.target.value)} />
            </div>
            <div className="setupWizard__field">
              <label htmlFor={`${id}-description`} className="setupWizard__label">Description</label>
              <textarea id={`${id}-description`} className="setupWizard__textarea" value={editor.description} rows={3}
                placeholder="What will you be collecting?" onChange={event => editor.setDescription(event.target.value)} />
            </div>
          </>}
          {tab === 'Theme' && <>
            <p className="setupWizard__hint">Choose a theme with pre-configured templates and categories. You can customize these later.</p>
            <SetupThemePicker themes={themes} loading={themesLoading} error={themesError} retry={loadThemes}
              selectedId={editor.selectedTheme?.themeId} select={editor.selectTheme} />
          </>}
          {tab === 'Preview' && (editor.selectedTheme ? <>
            <div className="setupWizard__summary">
              <h3 className="setupWizard__summaryTitle">Collection Summary</h3>
              <dl className="setupWizard__summaryList">
                <dt>Name</dt><dd>{editor.name}</dd>
                {editor.description && <><dt>Description</dt><dd>{editor.description}</dd></>}
                <dt>Theme</dt><dd>{editor.selectedTheme.name}</dd>
              </dl>
            </div>
            <ThemePreview theme={editor.selectedTheme} />
          </> : <ContentState kind="empty" title="Choose an available theme before creating the collection" />)}
        </div>
        <div className="setupWizard__footer">
          <button type="button" className="setupWizard__btn setupWizard__btn--secondary" disabled={tab === 'Basics'}
            onClick={() => setTab(tab === 'Preview' ? 'Theme' : 'Basics')}>Previous</button>
          {tab === 'Preview' ? <button type="button" className="setupWizard__btn setupWizard__btn--primary" disabled={!canOpen.Preview}
            onClick={() => void editor.create(false)}>{editor.pending ? 'Creating...' : 'Create Collection'}</button> :
            <button type="button" className="setupWizard__btn setupWizard__btn--primary" disabled={tab === 'Basics' ? !canOpen.Theme : !canOpen.Preview}
              onClick={() => setTab(tab === 'Basics' ? 'Theme' : 'Preview')}>Next</button>}
        </div>
      </fieldset>
    </div>
  </section>;
}

export default CollectionSetupWizard;
