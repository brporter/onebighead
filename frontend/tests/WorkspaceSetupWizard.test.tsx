import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import { ApiError } from '../src/api/transport';
import { setupAttemptStorage } from '../src/data/onboarding/setupAttemptStorage';
import WorkspaceSetupWizard from '../src/components/wizard/WorkspaceSetupWizard';
import { useUser } from '../src/contexts/useUser';
import { useCollectionsData as useDataHook } from '../src/contexts/useData';
import { authApi, workspacesApi } from '../src/api';
import { createMockCollection, createMockCollectionTheme, createMockCurrentUser, createMockDataContextValue } from './testUtils';
import { deferred } from './testUtils/deferred';
import { WorkspaceRole } from '../src/utils/types';

const useData = useDataHook as () => import('./testUtils/dataTypes').DataContextValue;

vi.mock('../src/contexts/useUser', () => ({ useUser: vi.fn() }));
vi.mock('../src/contexts/useData', async () => {
  const { mockDataHooks } = await import('./testUtils/mockDataHooks');
  return mockDataHooks({ useData: vi.fn() });
});
vi.mock('../src/api', () => ({ authApi: { completeWelcome: vi.fn(), acceptTerms: vi.fn() }, workspacesApi: { setup: vi.fn(), switch: vi.fn() } }));

const themes = [createMockCollectionTheme({ name: 'General' }), createMockCollectionTheme({ themeId: 2, name: 'Books' })];
const created = { workspaceId: 8, workspaceName: 'Study', collectionId: 12, collectionName: 'My Collection', workspaceRole: WorkspaceRole.WorkspaceAdmin };
const refetch = vi.fn();
const complete = vi.fn();
const cancel = vi.fn();
const skip = vi.fn();
let data: ReturnType<typeof createMockDataContextValue>;
let session: ReturnType<typeof useUser>;

beforeEach(() => {
  sessionStorage.clear();
  vi.resetAllMocks();
  session = { user: createMockCurrentUser(), loading: false, error: null, signedOut: false, refetch, logout: vi.fn() };
  data = createMockDataContextValue({ themes });
  vi.mocked(useUser).mockImplementation(() => session);
  vi.mocked(useData).mockImplementation(() => data);
  vi.mocked(workspacesApi.setup).mockResolvedValue(created);
  vi.mocked(authApi.completeWelcome).mockResolvedValue({ workspaceId: 1, workspaceName: 'Study', hasCompletedWelcome: true, collectionId: 12, collectionName: 'Books' });
  vi.mocked(authApi.acceptTerms).mockResolvedValue({ hasAcceptedTerms: true, acceptedTermsAt: '2026-11-10' });
  refetch.mockResolvedValue(undefined);
  vi.mocked(data.setupCollection).mockResolvedValue(createMockCollection({ collectionId: 12 }));
});
const button = (name: string) => screen.getByRole('button', { name });
const field = (name: RegExp) => screen.getByRole('textbox', { name });
const change = (name: RegExp, value: string) => fireEvent.change(field(name), { target: { value } });
async function preview() {
  fireEvent.click(button('Next'));
  fireEvent.click(button('Next'));
  expect(screen.getByText('Setup Summary')).toBeInTheDocument();
}

it('requires all earlier steps and keeps entered details across tab and previous navigation', async () => {
  const user = userEvent.setup();
  render(<WorkspaceSetupWizard onComplete={complete} />);
  expect(screen.getByRole('heading', { name: 'Create New Workspace', level: 2 })).toBeInTheDocument();
  expect(button('Theme')).toBeDisabled();
  expect(button('Preview')).toBeDisabled();
  expect(button('Next')).toBeDisabled();
  expect(field(/New Workspace Name/)).toHaveAttribute('maxlength', '200');
  expect(field(/Collection Name/)).toHaveAttribute('maxlength', '200');
  expect(field(/Description/)).toHaveAttribute('maxlength', '1000');
  change(/New Workspace Name/, '  Study  ');
  change(/Collection Name/, '  Editions  ');
  change(/Description/, '  Signed copies  ');
  await user.click(button('Next'));
  await user.click(screen.getByRole('button', { name: /Books/ }));
  await user.click(button('Next'));
  expect(screen.getByText('Signed copies')).toBeInTheDocument();
  await user.click(button('Previous'));
  await user.click(button('Previous'));
  expect(field(/New Workspace Name/)).toHaveValue('  Study  ');
  await user.click(button('Theme'));
  await user.click(button('Preview'));
  expect(button('Preview')).toHaveAttribute('aria-current', 'step');
  await user.click(button('Create Workspace'));
  await waitFor(() => expect(complete).toHaveBeenCalledWith(created));
  expect(workspacesApi.setup).toHaveBeenCalledWith({ requestId: expect.any(String), workspaceName: 'Study', collectionName: 'Editions', collectionDescription: 'Signed copies', themeId: 2 });
  expect(workspacesApi.switch).not.toHaveBeenCalled();
  expect(refetch).toHaveBeenCalledWith({ throwOnError: true });
});

it('keeps a failed creation editable and retries only refresh after creation is confirmed', async () => {
  const setup = deferred<typeof created>();
  const refresh = deferred<void>();
  vi.mocked(workspacesApi.setup).mockRejectedValueOnce(new ApiError('Cannot create', 400, 'Bad request')).mockReturnValueOnce(setup.promise);
  refetch.mockRejectedValueOnce(new Error('Cannot refresh')).mockReturnValueOnce(refresh.promise);
  render(<WorkspaceSetupWizard onComplete={complete} onCancel={cancel} />);
  change(/New Workspace Name/, 'Study');
  await preview();
  expect(screen.getByText('My Collection')).toBeInTheDocument();
  fireEvent.click(button('Create Workspace'));
  expect(await screen.findByRole('alert')).toHaveTextContent('Cannot create');
  expect(button('Details')).toBeEnabled();
  fireEvent.click(button('Create Workspace'));
  expect(button('Finishing setup...')).toBeDisabled();
  expect(button('Details')).toBeDisabled();
  expect(screen.queryByRole('button', { name: 'Previous' })).not.toBeInTheDocument();
  expect(button('Close setup')).toBeDisabled();
  fireEvent.click(button('Finishing setup...'));
  expect(workspacesApi.setup).toHaveBeenCalledTimes(2);
  await act(async () => setup.resolve(created));
  expect(screen.getByRole('alert')).toHaveTextContent('Cannot refresh');
  expect(complete).not.toHaveBeenCalled();
  expect(button('Details')).toBeDisabled();
  expect(button('Close setup')).toBeEnabled();
  fireEvent.click(button('Continue setup'));
  expect(button('Finishing setup...')).toBeDisabled();
  await act(async () => refresh.resolve());
  expect(complete).toHaveBeenCalledWith(created);
  expect(workspacesApi.setup).toHaveBeenCalledTimes(2);
  expect(refetch).toHaveBeenCalledTimes(2);
  expect(workspacesApi.setup).toHaveBeenLastCalledWith({ requestId: expect.any(String), workspaceName: 'Study', collectionName: undefined, collectionDescription: undefined, themeId: 1 });
});

it('protects unsaved details and theme selection while allowing a clean cancellation', async () => {
  const confirmation = vi.spyOn(window, 'confirm').mockReturnValue(false);
  render(<WorkspaceSetupWizard onComplete={complete} onCancel={cancel} />);
  fireEvent.click(button('Cancel'));
  expect(cancel).toHaveBeenCalledOnce();
  expect(confirmation).not.toHaveBeenCalled();
  for (const name of [/New Workspace Name/, /Collection Name/, /Description/]) {
    change(name, 'Changed');
    fireEvent.click(button('Cancel'));
    expect(cancel).toHaveBeenCalledOnce();
    change(name, '');
  }
  change(/New Workspace Name/, 'Study');
  fireEvent.click(button('Next'));
  fireEvent.click(screen.getByRole('button', { name: /Books/ }));
  fireEvent.click(button('Details'));
  change(/New Workspace Name/, '');
  fireEvent.click(button('Cancel'));
  expect(cancel).toHaveBeenCalledOnce();
  confirmation.mockReturnValue(true);
  fireEvent.click(button('Cancel'));
  expect(cancel).toHaveBeenCalledTimes(2);
  expect(confirmation).toHaveBeenLastCalledWith('You have unsaved changes. Discard them?');
  confirmation.mockRestore();
});

it('keeps every later step locked until terms acceptance and required session refresh both succeed', async () => {
  session.user = createMockCurrentUser({ hasAcceptedTerms: false });
  refetch.mockRejectedValueOnce(new Error('Terms refresh failed')).mockResolvedValue(undefined);
  const user = userEvent.setup();
  render(<WorkspaceSetupWizard isWelcome showTerms onComplete={complete} onSkip={skip} />);
  for (const name of ['Welcome', 'Theme', 'Preview']) expect(button(name)).toBeDisabled();
  expect(screen.queryByRole('button', { name: 'Skip Setup' })).not.toBeInTheDocument();
  await user.click(button('Terms'));
  for (const checkbox of screen.getAllByRole('checkbox')) await user.click(checkbox);
  await user.click(button('Accept and Continue'));
  expect(await screen.findByRole('alert')).toHaveTextContent('Terms refresh failed');
  expect(button('Preview')).toBeDisabled();
  await user.click(button('Accept and Continue'));
  expect(await screen.findByText('Welcome to OneBigHead!')).toBeInTheDocument();
  expect(authApi.acceptTerms).toHaveBeenCalledOnce();
  expect(refetch).toHaveBeenCalledWith({ throwOnError: true });
  expect(button('Terms')).toBeDisabled();
  expect(button('Preview')).toBeDisabled();
  change(/First Collection Name/, 'Books');
  await preview();
  await user.click(button('Get Started'));
  await waitFor(() => expect(complete).toHaveBeenCalledWith(expect.objectContaining({ collectionId: 12, workspaceId: 1 })));
  expect(data.setupCollection).not.toHaveBeenCalled();
  expect(data.loadCollections).toHaveBeenCalledWith({ throwOnError: true });
  expect(authApi.completeWelcome).toHaveBeenCalledWith({ workspaceName: 'test@example.com', collection: { name: 'Books', description: '', themeId: 1 } });
});

it('resumes a skipped welcome without submitting it twice and blocks edits during pending work', async () => {
  const refresh = deferred<void>();
  refetch.mockRejectedValueOnce(new Error('Skip refresh failed')).mockReturnValueOnce(refresh.promise);
  render(<WorkspaceSetupWizard isWelcome onComplete={complete} onSkip={skip} />);
  fireEvent.click(button('Skip Setup'));
  expect(await screen.findByRole('alert')).toHaveTextContent('Skip refresh failed');
  expect(field(/Organization/)).toBeDisabled();
  expect(button('Skip Setup')).toBeDisabled();
  fireEvent.click(button('Continue setup'));
  expect(button('Finishing setup...')).toBeDisabled();
  await act(async () => refresh.resolve());
  expect(authApi.completeWelcome).toHaveBeenCalledExactlyOnceWith({});
  expect(skip).toHaveBeenCalledOnce();
  expect(data.setupCollection).not.toHaveBeenCalled();
  expect(complete).not.toHaveBeenCalled();
});

it('shows theme read failures and empty/loading states, retries, and invalidates a removed selection', async () => {
  data.themes = [];
  data.themesLoading = true;
  const element = <WorkspaceSetupWizard onComplete={complete} />;
  const { rerender } = render(element);
  change(/New Workspace Name/, 'Study');
  fireEvent.click(button('Next'));
  expect(screen.getByText('Loading themes...')).toBeInTheDocument();
  expect(button('Next')).toBeDisabled();
  data.themesLoading = false;
  data.themesError = 'Theme service offline';
  rerender(<WorkspaceSetupWizard onComplete={complete} />);
  expect(screen.getByRole('alert')).toHaveTextContent('Theme service offline');
  fireEvent.click(button('Try again'));
  data.themesError = null;
  rerender(<WorkspaceSetupWizard onComplete={complete} />);
  expect(screen.getByText('No themes available')).toBeInTheDocument();
  fireEvent.click(button('Try again'));
  expect(data.loadThemes).toHaveBeenCalledTimes(3);
  data.themes = [themes[1]];
  rerender(<WorkspaceSetupWizard onComplete={complete} />);
  expect(button('Next')).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: /Books/ }));
  fireEvent.click(button('Next'));
  data.themes = [themes[0]];
  rerender(<WorkspaceSetupWizard onComplete={complete} />);
  expect(screen.getByText('Choose an available theme before creating the workspace')).toBeInTheDocument();
  expect(button('Create Workspace')).toBeDisabled();
  fireEvent.click(button('Previous'));
  fireEvent.click(screen.getByRole('button', { name: /General/ }));
  expect(button('Next')).toBeEnabled();
});

it('waits for identity, retains drafts during refresh, and resets them for a different user', () => {
  session.loading = true;
  const { rerender } = render(<WorkspaceSetupWizard isWelcome onComplete={complete} />);
  expect(screen.getByRole('status')).toHaveTextContent('Loading workspace...');
  session.loading = false;
  session.user = null;
  rerender(<WorkspaceSetupWizard isWelcome onComplete={complete} />);
  expect(screen.getByRole('status')).toHaveTextContent('Loading workspace...');
  session.user = createMockCurrentUser();
  rerender(<WorkspaceSetupWizard isWelcome onComplete={complete} />);
  change(/Organization/, 'My draft');
  session.user = createMockCurrentUser({ email: 'updated@example.com' });
  rerender(<WorkspaceSetupWizard isWelcome onComplete={complete} />);
  expect(field(/Organization/)).toHaveValue('My draft');
  session.user = createMockCurrentUser({ workspaceId: 2, email: 'updated@example.com' });
  rerender(<WorkspaceSetupWizard isWelcome onComplete={complete} />);
  expect(field(/Organization/)).toHaveValue('updated@example.com');
  change(/Organization/, 'Second workspace draft');
  session.user = createMockCurrentUser({ userId: 2, email: 'other@example.com' });
  rerender(<WorkspaceSetupWizard isWelcome onComplete={complete} />);
  expect(field(/Organization/)).toHaveValue('other@example.com');
});

it('reports terms edits and pending acceptance through session refresh, then releases its status on unmount', async () => {
  session.user = createMockCurrentUser({ hasAcceptedTerms: false });
  const accepting = deferred<{ hasAcceptedTerms: boolean; acceptedTermsAt: string }>();
  const refreshing = deferred<void>();
  const status = vi.fn();
  vi.mocked(authApi.acceptTerms).mockReturnValue(accepting.promise);
  refetch.mockReturnValue(refreshing.promise);
  const view = render(<WorkspaceSetupWizard isWelcome showTerms onComplete={complete} onStatusChange={status} />);
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: false });
  const boxes = screen.getAllByRole('checkbox');
  fireEvent.click(boxes[1]);
  expect(status).toHaveBeenLastCalledWith({ dirty: true, pending: false });
  fireEvent.click(boxes[0]);
  fireEvent.click(button('Accept and Continue'));
  expect(status).toHaveBeenLastCalledWith({ dirty: true, pending: true });
  await act(async () => accepting.resolve({ hasAcceptedTerms: true, acceptedTermsAt: '2026-11-10' }));
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: true });
  await act(async () => refreshing.resolve());
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: false });
  change(/First Collection Name/, 'Books');
  expect(status).toHaveBeenLastCalledWith({ dirty: true, pending: false });
  view.unmount();
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: false });
});

it('gives separate wizard instances unique labels and ignores a late completion after unmount', async () => {
  const setup = deferred<typeof created>();
  vi.mocked(workspacesApi.setup).mockReturnValue(setup.promise);
  const first = render(<WorkspaceSetupWizard onComplete={complete} />);
  const second = render(<WorkspaceSetupWizard onComplete={vi.fn()} />);
  const inputs = screen.getAllByRole('textbox', { name: /New Workspace Name/ });
  expect(inputs[0].id).not.toEqual(inputs[1].id);
  second.unmount();
  change(/New Workspace Name/, 'Study');
  await preview();
  fireEvent.click(within(first.container).getByRole('button', { name: 'Create Workspace' }));
  first.unmount();
  await act(async () => setup.resolve(created));
  expect(complete).not.toHaveBeenCalled();
});

it('retains a confirmed welcome while retrying a failed collection cache refresh', async () => {
  vi.mocked(data.loadCollections).mockRejectedValueOnce(new Error('Collections unavailable')).mockResolvedValue(undefined);
  render(<WorkspaceSetupWizard isWelcome onComplete={complete} />);
  change(/First Collection Name/, 'Books');
  await preview();
  fireEvent.click(button('Get Started'));
  expect(await screen.findByRole('alert')).toHaveTextContent('Collections unavailable');
  expect(complete).not.toHaveBeenCalled();
  expect(button('Welcome')).toBeDisabled();
  fireEvent.click(button('Continue setup'));
  await waitFor(() => expect(complete).toHaveBeenCalledWith(expect.objectContaining({ collectionId: 12 })));
  expect(authApi.completeWelcome).toHaveBeenCalledOnce();
  expect(data.loadCollections).toHaveBeenCalledTimes(2);
  expect(data.loadCollections).toHaveBeenLastCalledWith({ throwOnError: true });
});

it('recovers an uncertain creation after remount with its original details and request ID', async () => {
  const confirmation = vi.spyOn(window, 'confirm');
  vi.mocked(workspacesApi.setup).mockRejectedValueOnce(new ApiError('Response lost', 0, 'Network error'));
  const first = render(<WorkspaceSetupWizard onComplete={complete} onCancel={cancel} />);
  change(/New Workspace Name/, 'Study');
  change(/Collection Name/, 'Books');
  change(/Description/, 'Editions');
  await preview();
  fireEvent.click(button('Create Workspace'));
  expect(await screen.findByRole('alert')).toHaveTextContent('Response lost');
  expect(button('Details')).toBeDisabled();
  const request = vi.mocked(workspacesApi.setup).mock.calls[0][0];
  expect(setupAttemptStorage(session.user!.userId).read()?.requestId).toBe(request.requestId);
  fireEvent.click(button('Close setup'));
  expect(cancel).toHaveBeenCalledOnce();
  expect(confirmation).not.toHaveBeenCalled();
  first.unmount();
  render(<WorkspaceSetupWizard onComplete={complete} onCancel={cancel} />);
  expect(field(/New Workspace Name/)).toHaveValue('Study');
  expect(field(/Collection Name/)).toHaveValue('Books');
  expect(field(/Description/)).toHaveValue('Editions');
  expect(field(/New Workspace Name/)).toBeDisabled();
  fireEvent.click(button('Continue setup'));
  await waitFor(() => expect(complete).toHaveBeenCalledWith(created));
  expect(workspacesApi.setup).toHaveBeenLastCalledWith(request);
  expect(setupAttemptStorage(session.user!.userId).read()).toBeUndefined();
  confirmation.mockRestore();
});

it.each([true, false])('shows storage initialization failure without discarding a pending attempt (cancel=%s)', allowCancel => {
  const read = vi.spyOn(window, 'sessionStorage', 'get').mockImplementation(() => { throw new Error('Storage blocked'); });
  render(<WorkspaceSetupWizard onComplete={complete} onCancel={allowCancel ? cancel : undefined} />);
  expect(screen.getByRole('alert')).toHaveTextContent('Storage blocked');
  expect(workspacesApi.setup).not.toHaveBeenCalled();
  if (allowCancel) {
    fireEvent.click(button('Close setup'));
    expect(cancel).toHaveBeenCalledOnce();
  }
  read.mockRestore();
  fireEvent.click(button('Try again'));
  expect(field(/New Workspace Name/)).toHaveValue('');
});
