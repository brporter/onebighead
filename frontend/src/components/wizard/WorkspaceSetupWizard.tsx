import { useEffect, useId, useState } from 'react';
import { useUser } from '../../contexts/useUser';
import { useThemesData, useCollectionsData } from '../../contexts/useData';
import { authApi, workspacesApi } from '../../api';
import type { CurrentUser } from '../../utils/types';
import { useAsyncAction } from '../../utils/useAsyncAction';
import { getErrorMessage } from '../../utils/errorUtils';
import { createWelcomeFlow, createWorkspaceFlow, type SetupFlow, type WorkspaceSetupResult } from '../../data/onboarding/setupFlow';
import { setupAttemptStorage } from '../../data/onboarding/setupAttemptStorage';
import { useEditorStatus, type EditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import { ContentState } from '../common/ContentState';
import { TermsAcceptance } from '../common/TermsAcceptance';
import { SetupThemePicker } from '../collection/SetupThemePicker';
import ThemePreview from '../collection/ThemePreview';
import '../../styles/components/WorkspaceSetupWizard.css';

export type { WorkspaceSetupResult } from '../../data/onboarding/setupFlow';
interface WorkspaceSetupWizardProps {
  showTerms?: boolean;
  isWelcome?: boolean;
  onComplete: (result: WorkspaceSetupResult) => void;
  onCancel?: () => void;
  onSkip?: () => void;
  onStatusChange?: EditorStatusListener;
}
type Step = 'terms' | 'details' | 'theme' | 'preview';

function WorkspaceSetupWizard(props: WorkspaceSetupWizardProps) {
  const { user, loading } = useUser();
  if (loading || !user) return <ContentState kind="loading" title="Loading workspace..." />;
  return <SetupFlowSession key={`${user.userId}:${props.isWelcome ? user.workspaceId : 'new'}`} {...props} user={user} />;
}

function SetupFlowSession(props: WorkspaceSetupWizardProps & { user: CurrentUser }) {
  const { refetch } = useUser();
  const { loadCollections } = useCollectionsData();
  function initialize(): { flow: SetupFlow; error?: never } | { flow?: never; error: string } {
    try {
      const refresh = () => refetch({ throwOnError: true });
      return { flow: props.isWelcome ? createWelcomeFlow(authApi.completeWelcome, async () => {
        await refresh();
        await loadCollections({ throwOnError: true });
      }) : createWorkspaceFlow(workspacesApi.setup, refresh, setupAttemptStorage(props.user.userId)) };
    } catch (error) { return { error: getErrorMessage(error, 'Unable to recover workspace setup') }; }
  }
  const [state, setState] = useState(initialize);
  if (!state.flow) return <ContentState kind="error" title="Unable to recover workspace setup"
    action={<><button type="button" onClick={() => setState(initialize())}>Try again</button>
      {props.onCancel && <button type="button" onClick={props.onCancel}>Close setup</button>}</>}>{state.error}</ContentState>;
  return <SetupSession {...props} flow={state.flow} />;
}

function SetupSession({ user, flow, showTerms = false, isWelcome = false, onComplete, onCancel, onSkip, onStatusChange }: WorkspaceSetupWizardProps & { user: CurrentUser; flow: SetupFlow }) {
  const { refetch } = useUser();
  const { themes, themesLoading, themesError, loadThemes } = useThemesData();
  const [termsAccepted, setTermsAccepted] = useState(user.hasAcceptedTerms);
  const [step, setStep] = useState<Step>(showTerms && !user.hasAcceptedTerms ? 'terms' : 'details');
  const [initialName] = useState(isWelcome ? user.email : '');
  const [workspaceName, setWorkspaceName] = useState(flow.draft?.workspaceName ?? initialName);
  const [collectionName, setCollectionName] = useState(flow.draft?.collectionName ?? '');
  const [description, setDescription] = useState(flow.draft?.description ?? '');
  const [selectedId, selectTheme] = useState<number | null>(flow.draft?.themeId ?? null);
  const [resume, setResume] = useState<(() => void)>();
  const [termsStatus, setTermsStatus] = useState<EditorStatus>({ dirty: false, pending: false });
  const action = useAsyncAction();
  const id = useId();
  const general = themes.find(theme => theme.name === 'General');
  const selectedTheme = themes.find(theme => theme.themeId === (selectedId ?? general?.themeId));
  const locked = action.pending || flow.started;
  const dirty = workspaceName !== initialName || collectionName !== '' || description !== '' || selectedId !== null;
  useEditorStatus(dirty || termsStatus.dirty, locked || termsStatus.pending, onStatusChange);
  const detailsValid = !!workspaceName.trim() && (!isWelcome || !!collectionName.trim());
  const termsValid = !showTerms || termsAccepted;
  const themeValid = !!selectedTheme && !themesLoading && !themesError;
  const available = { terms: !termsAccepted, details: termsValid, theme: termsValid && detailsValid, preview: termsValid && detailsValid && themeValid };
  const steps: { id: Step; label: string }[] = [
    ...(showTerms ? [{ id: 'terms' as const, label: 'Terms' }] : []),
    { id: 'details', label: isWelcome ? 'Welcome' : 'Details' },
    { id: 'theme', label: 'Theme' }, { id: 'preview', label: 'Preview' },
  ];
  const Heading = isWelcome ? 'h1' : 'h2';
  const skip = flow.skip;
  useEffect(() => { void loadThemes(); }, [loadThemes]);

  function start<T>(operation: () => Promise<T>, onSuccess: (result: T) => void) {
    const run = () => { void action.run(operation, 'Failed to complete setup', onSuccess); };
    setResume(() => run);
    run();
  }

  return <section className={`workspace-setup setupWizard${isWelcome ? '' : ' setupWizard--modal'}`} aria-labelledby={`${id}-title`}>
    <div className="setupWizard__container">
      <div className="setupWizard__header">
        <Heading id={`${id}-title`} className="setupWizard__title">{isWelcome ? 'Get Started' : 'Create New Workspace'}</Heading>
        <div className="setupWizard__headerActions">
          {!isWelcome && onCancel && step !== 'terms' && <button type="button" className="setupWizard__cancelBtn" disabled={action.pending} onClick={() => {
            if (flow.draft || !dirty || window.confirm('You have unsaved changes. Discard them?')) onCancel();
          }}>{flow.draft ? 'Close setup' : 'Cancel'}</button>}
          {skip && onSkip && step !== 'terms' && <button type="button" className="setupWizard__skipBtn" disabled={locked}
            onClick={() => start(skip, onSkip)}>Skip Setup</button>}
        </div>
      </div>
      {action.error && <ContentState kind="error" title="Unable to finish setup">{action.error}</ContentState>}
      {flow.started && <div className="workspace-setup__continuation" role="status">
        <p>Your setup details are kept. Continue to check the result and finish setup.</p>
        <button type="button" className="setupWizard__btn setupWizard__btn--primary" disabled={action.pending}
          onClick={resume ?? (() => start(() => flow.complete(flow.draft!), onComplete))}>
          {action.pending ? 'Finishing setup...' : 'Continue setup'}
        </button>
      </div>}
      <div className="workspace-setup__body">
        <fieldset className="workspace-setup__fields" disabled={locked} aria-busy={action.pending}>
          <nav className="setupWizard__tabs" aria-label="Workspace setup steps">
            {steps.map((item, index) => <button type="button" key={item.id} className={`setupWizard__tab${step === item.id ? ' setupWizard__tab--active' : ''}`}
              aria-current={step === item.id ? 'step' : undefined} disabled={!available[item.id]} onClick={() => setStep(item.id)}>
              <span className="setupWizard__tabNumber" aria-hidden="true">{index + 1}</span>{item.label}
            </button>)}
          </nav>
          <div className="setupWizard__content">
            {step === 'terms' && <TermsAcceptance onStatusChange={setTermsStatus} onAccepted={async () => {
              await refetch({ throwOnError: true });
              setTermsAccepted(true);
              setStep('details');
            }} />}
            {step === 'details' && <>
              {isWelcome && <div className="workspace-setup__intro">
                <h2>Welcome to OneBigHead!</h2>
                <p>Let's get you set up. First, tell us a bit about yourself and your first collection.</p>
              </div>}
              <div className="setupWizard__field">
                <label htmlFor={`${id}-workspace`} className="setupWizard__label">{isWelcome ? 'Organization / Workspace Name' : 'New Workspace Name'}<span aria-hidden="true"> *</span></label>
                <input id={`${id}-workspace`} className="setupWizard__input" maxLength={200} value={workspaceName} onChange={event => setWorkspaceName(event.target.value)}
                  aria-required="true" aria-describedby={`${id}-hint`} autoFocus placeholder={isWelcome ? 'Your name, company, or workspace' : 'Enter workspace name'} />
                <p id={`${id}-hint`} className="setupWizard__hint">This is how your workspace will be identified.</p>
              </div>
              <div className="setupWizard__field">
                <label htmlFor={`${id}-collection`} className="setupWizard__label">{isWelcome ? 'First Collection Name' : 'Collection Name'}{isWelcome && <span aria-hidden="true"> *</span>}</label>
                <input id={`${id}-collection`} className="setupWizard__input" maxLength={200} value={collectionName} onChange={event => setCollectionName(event.target.value)} aria-required={isWelcome}
                  placeholder={isWelcome ? 'e.g., My Book Collection' : "Defaults to 'My Collection'"} />
              </div>
              <div className="setupWizard__field">
                <label htmlFor={`${id}-description`} className="setupWizard__label">Description</label>
                <textarea id={`${id}-description`} className="setupWizard__textarea" maxLength={1000} value={description} onChange={event => setDescription(event.target.value)} rows={3} placeholder="What will you be collecting?" />
              </div>
            </>}
            {step === 'theme' && <>
              <p className="setupWizard__hint">Choose a theme to get started with pre-configured templates and categories. You can always customize these later.</p>
              <SetupThemePicker themes={themes} loading={themesLoading} error={themesError} retry={loadThemes} selectedId={selectedTheme?.themeId} select={selectTheme} />
            </>}
            {step === 'preview' && (selectedTheme ? <>
              <div className="setupWizard__summary">
                <h3 className="setupWizard__summaryTitle">Setup Summary</h3>
                <dl className="setupWizard__summaryList">
                  <dt>Workspace Name</dt><dd>{workspaceName.trim()}</dd>
                  <dt>Collection Name</dt><dd>{collectionName.trim() || 'My Collection'}</dd>
                  {description.trim() && <><dt>Description</dt><dd>{description.trim()}</dd></>}
                  <dt>Theme</dt><dd>{selectedTheme.name}</dd>
                </dl>
              </div>
              <ThemePreview theme={selectedTheme} />
            </> : <ContentState kind="empty" title="Choose an available theme before creating the workspace" />)}
          </div>
          {step !== 'terms' && !flow.started && <div className="setupWizard__footer">
            <button type="button" className="setupWizard__btn setupWizard__btn--secondary" disabled={step === 'details'} onClick={() => setStep(step === 'preview' ? 'theme' : 'details')}>Previous</button>
            {step === 'preview' ? <button type="button" className="setupWizard__btn setupWizard__btn--primary" disabled={!available.preview}
              onClick={() => start(() => flow.complete({ workspaceName: workspaceName.trim(), collectionName: collectionName.trim(), description: description.trim(), themeId: selectedTheme!.themeId }), onComplete)}>
              {action.pending ? 'Creating...' : isWelcome ? 'Get Started' : 'Create Workspace'}
            </button> : <button type="button" className="setupWizard__btn setupWizard__btn--primary" disabled={step === 'details' ? !available.theme : !available.preview}
              onClick={() => setStep(step === 'details' ? 'theme' : 'preview')}>Next</button>}
          </div>}
        </fieldset>
      </div>
    </div>
  </section>;
}

export default WorkspaceSetupWizard;
