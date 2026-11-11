import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import SettingsView from '../../src/views/SettingsView';
import * as UserContext from '../../src/contexts/useUser';
import * as DataContext from '../../src/contexts/useData';
import * as exportApiModule from '../../src/api/export';
import { WorkspaceRole, Visibility } from '../../src/utils/types';
import type { Collection } from '../../src/utils/types';
import type { EditorStatusListener } from '../../src/data/shared/useEditorStatus';
import { deferred } from '../testUtils/deferred';
import { createMockDataContextValue } from '../testUtils';
import { workspacesApi } from '../../src/api/workspaces';

// React's generated prefix depends on earlier mounts. Keep these layout
// snapshots independent of test order; field associations are tested by label.
expect.addSnapshotSerializer({
  test: value => typeof value === 'string' && /_r_[a-z0-9]+_/.test(value),
  serialize: value => JSON.stringify(value.replace(/_r_[a-z0-9]+_/g, '_react-id_')),
});

// Mock the contexts
vi.mock('../../src/contexts/useUser', () => ({
  useUser: vi.fn(),
}));

vi.mock('../../src/contexts/useData', async () => {
  const { mockDataHooks } = await import('../testUtils/mockDataHooks');
  return mockDataHooks({
  useData: vi.fn(),
});
});

vi.mock('../../src/api/dashboard', () => ({ dashboardApi: { get: vi.fn(() => new Promise(() => {})) } }));

const mockRequestPublish = vi.fn();
const mockRequestUnpublish = vi.fn();
vi.mock('../../src/contexts/usePublish', () => ({
  usePublish: () => ({
    requestPublish: mockRequestPublish,
    requestUnpublish: mockRequestUnpublish,
    pendingIntent: null,
    clearIntent: vi.fn(),
  }),
}));

// Mock the export API
vi.mock('../../src/api/export', () => ({
  exportApi: {
    downloadExport: vi.fn(),
  },
}));

vi.mock('../../src/api/workspaces', async importOriginal => {
  const actual = await importOriginal<typeof import('../../src/api/workspaces')>();
  return { ...actual, workspacesApi: { ...actual.workspacesApi,
    getRestorableWorkspaces: vi.fn().mockResolvedValue([]),
    switch: vi.fn().mockResolvedValue({ success: true, workspaceId: 2, workspaceName: 'Other' }),
  } };
});

// Mock child components to simplify testing
vi.mock('../../src/components/template/ItemTemplateEditor', () => ({
  default: ({ onClose, onStatusChange }: { onClose: () => void; onStatusChange: EditorStatusListener }) => (
    <div data-testid="item-template-editor">
      <button onClick={onClose}>Close Template Editor</button>
      <button onClick={() => onStatusChange({ dirty: true, pending: false })}>Mark Dirty</button>
      <button onClick={() => onStatusChange({ dirty: true, pending: true })}>Saving template</button>
      <button onClick={() => onStatusChange({ dirty: false, pending: false })}>Template saved</button>
    </div>
  ),
}));

vi.mock('../../src/components/collection/CollectionTemplateEditor', () => ({
  default: ({ collection, onClose, onDirtyChange, onStatusChange }: { collection: Collection; onClose: () => void; onDirtyChange?: (dirty: boolean) => void; onStatusChange?: EditorStatusListener }) => (
    <div data-testid="collection-template-editor">
      <span>{`Editing templates for: ${collection.name}`}</span>
      <button onClick={onClose}>Close Collection Templates</button>
      <button onClick={() => { onDirtyChange?.(true); onStatusChange?.({ dirty: true, pending: false }); }}>Mark Collection Templates Dirty</button>
    </div>
  ),
}));

vi.mock('../../src/components/collection/CollectionSetupWizard', () => ({
  default: ({ onComplete, onCancel }: { onComplete: () => void; onCancel: () => void }) => (
    <div data-testid="collection-setup-wizard">
      <button onClick={onComplete}>Complete Setup</button>
      <button onClick={onCancel}>Cancel Setup</button>
    </div>
  ),
}));

vi.mock('../../src/components/wizard/WorkspaceSetupWizard', () => ({
  default: ({ onComplete, onCancel }: { onComplete: () => void; onCancel?: () => void }) => (
    <div data-testid="workspace-setup-wizard">
      <button onClick={onComplete}>Complete Workspace Setup</button>
      {onCancel && <button onClick={onCancel}>Cancel Workspace Setup</button>}
    </div>
  ),
}));

vi.mock('../../src/components/support/SupportSection', () => ({
  SupportSection: ({ isFullPage, onNewRequest, refreshKey, onStatusChange }: { isFullPage: boolean; onNewRequest: () => void; refreshKey: number; onStatusChange: EditorStatusListener }) => (
    <div data-testid="support-section" data-refresh={refreshKey}>Support Section (fullPage: {isFullPage.toString()})<button onClick={onNewRequest}>New support request</button>
      <button onClick={() => onStatusChange({ dirty: true, pending: false })}>Draft support reply</button>
      <button onClick={() => onStatusChange({ dirty: true, pending: true })}>Sending support reply</button>
      <button onClick={() => onStatusChange({ dirty: false, pending: false })}>Support reply sent</button>
    </div>
  ),
}));

// Mock the barrel export for user components
vi.mock('../../src/components/user', () => ({
  AccountDeletionSection: () => <div>Account deletion settings</div>,
  UserButton: () => <button data-testid="user-button">User Button</button>,
  UserManagement: ({ onStatusChange }: { onStatusChange?: EditorStatusListener }) => (
    <div data-testid="user-management">
      <span>User Management</span>
      <button onClick={() => onStatusChange?.({ dirty: true, pending: false })}>Mark Team Dirty</button>
      <button onClick={() => onStatusChange?.({ dirty: true, pending: true })}>Saving team change</button>
      <button onClick={() => onStatusChange?.({ dirty: false, pending: false })}>Team change saved</button>
    </div>
  ),
}));

vi.mock('../../src/components/support/SupportModal', () => ({
  SupportModal: ({ isOpen, onClose, onSuccess }: { isOpen: boolean; onClose: () => void; onSuccess: () => void }) =>
    isOpen ? (
      <div data-testid="support-modal">
        <button onClick={onClose}>Close Support Modal</button>
        <button onClick={onSuccess}>Send support request</button>
      </div>
    ) : null,
}));

vi.mock('../../src/components/workspace', () => ({
  WorkspaceEditModal: ({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) =>
    isOpen ? (
      <div data-testid="workspace-edit-modal">
        <button onClick={onClose}>Close Workspace Modal</button>
      </div>
    ) : null,
}));

vi.mock('../../src/components/category', () => ({
  CategoryManagerModal: ({ collectionId, isOpen, onClose }: { collectionId: number; isOpen: boolean; onClose: () => void }) =>
    isOpen ? (
      <div data-testid="category-manager-modal" data-collection-id={collectionId}>
        <button onClick={onClose}>Close Category Manager</button>
      </div>
    ) : null,
}));

vi.mock('../../src/components/common', async () => {
  const actual = await vi.importActual('../../src/components/common');
  return {
    ...actual,
    SiteHeader: ({ children }: { children?: React.ReactNode }) => (
      <header data-testid="site-header">
        <span>Site Header</span>
        {children}
      </header>
    ),
    SiteFooter: () => <footer data-testid="site-footer">Site Footer</footer>,
  };
});

// Mock window.confirm
const mockConfirm = vi.fn();
window.confirm = mockConfirm;

describe('SettingsView', () => {
  afterEach(() => vi.unstubAllGlobals());
  const mockWorkspaceMembership = {
    workspaceId: 1,
    workspaceName: 'Test Workspace',
    workspaceRole: WorkspaceRole.WorkspaceAdmin,
    hasCompletedWelcome: true,
  };

  const mockAdminUser = {
    userId: 1,
    email: 'admin@example.com',
    workspaceId: 1,
    workspaceName: 'Test Workspace',
    hasCompletedWelcome: true,
    hasAcceptedTerms: true,
    isSystemAdministrator: false,
    workspaceRole: WorkspaceRole.WorkspaceAdmin,
    isWorkspaceAdmin: true,
    activeWorkspace: mockWorkspaceMembership,
    workspaces: [mockWorkspaceMembership],
  };

  const mockNormalUserWorkspace = {
    workspaceId: 1,
    workspaceName: 'Test Workspace',
    workspaceRole: WorkspaceRole.Normal,
    hasCompletedWelcome: true,
  };

  const mockNormalUser = {
    userId: 2,
    email: 'member@example.com',
    workspaceId: 1,
    workspaceName: 'Test Workspace',
    hasCompletedWelcome: true,
    hasAcceptedTerms: true,
    isSystemAdministrator: false,
    workspaceRole: WorkspaceRole.Normal,
    isWorkspaceAdmin: false,
    activeWorkspace: mockNormalUserWorkspace,
    workspaces: [mockNormalUserWorkspace],
  };

  const mockCollections: Collection[] = [
    {
      collectionId: 1,
      workspaceId: 1,
      name: 'Test Collection 1',
      description: 'First collection description',
      heroImageUrl: 'https://example.com/hero1.jpg',
      visibility: Visibility.Public,
      effectiveIsPublic: true,
      slug: 'test-collection-1',
    },
    {
      collectionId: 2,
      workspaceId: 1,
      name: 'Test Collection 2',
      description: 'Second collection description',
      heroImageUrl: null,
      visibility: Visibility.Private,
      effectiveIsPublic: false,
      slug: 'test-collection-2',
    },
  ];

  const mockAddCollection = vi.fn();
  const mockUpdateCollection = vi.fn();
  const mockDeleteCollection = vi.fn();
  const mockLoadCollections = vi.fn();

  const renderWithRouter = (initialEntries: string[] = ['/settings?section=collections']) => {
    const router = createMemoryRouter([
      { path: '/settings', element: <SettingsView /> },
      { path: '/collections', element: <div>Collection overview</div> },
    ], { initialEntries });
    return { ...render(<RouterProvider router={router} />), router };
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockConfirm.mockReturnValue(true);
    mockUpdateCollection.mockReset().mockResolvedValue(undefined);
    mockDeleteCollection.mockReset().mockResolvedValue(undefined);
    mockLoadCollections.mockReset().mockResolvedValue(undefined);

    vi.mocked(UserContext.useUser).mockReturnValue({
      user: mockAdminUser,
      loading: false,
      error: null,
      signedOut: false, refetch: vi.fn(),
      logout: vi.fn(),
    });

    vi.mocked(DataContext.useCollectionsData).mockReturnValue(createMockDataContextValue({
      collections: mockCollections,
      addCollection: mockAddCollection,
      updateCollection: mockUpdateCollection,
      deleteCollection: mockDeleteCollection,
      loadCollections: mockLoadCollections,
    }));

    vi.mocked(exportApiModule.exportApi.downloadExport).mockResolvedValue({
      blob: new Blob(['test data'], { type: 'application/zip' }),
      filename: 'export.zip',
    });
  });

  describe('layout and navigation', () => {
    it('composes workspace settings with session refresh and creation destinations', async () => {
      const reload = vi.fn();
      const refetch = vi.fn().mockResolvedValue(undefined);
      vi.stubGlobal('location', { href: '', reload });
      vi.mocked(UserContext.useUser).mockReturnValue({ user: { ...mockAdminUser, workspaces: [mockWorkspaceMembership, { ...mockNormalUserWorkspace, workspaceId: 2, workspaceName: 'Other' }] }, loading: false, error: null, signedOut: false, refetch, logout: vi.fn() });
      const { router } = renderWithRouter(['/settings?section=workspaces']);
      await userEvent.click(screen.getByRole('button', { name: 'Switch to Other' }));
      await waitFor(() => expect(refetch).toHaveBeenCalledExactlyOnceWith({ throwOnError: true, endSessionIfAnonymous: true }));
      expect(reload).not.toHaveBeenCalled();
      vi.spyOn(workspacesApi, 'update').mockResolvedValue({ workspaceId: 1, workspaceName: 'Updated workspace' });
      await userEvent.click(screen.getByRole('button', { name: `Edit ${mockWorkspaceMembership.workspaceName}` }));
      const edit = await screen.findByRole('dialog', { name: 'Edit Workspace' });
      await userEvent.click(within(edit).getByRole('button', { name: 'Save' }));
      await waitFor(() => expect(refetch).toHaveBeenCalledTimes(2));
      expect(reload).not.toHaveBeenCalled();
      await userEvent.click(screen.getByRole('button', { name: '+ Create New Workspace' }));
      await userEvent.click(screen.getByRole('button', { name: 'Complete Workspace Setup' }));
      expect(router.state.location.pathname + router.state.location.search).toBe('/settings?section=workspaces');
      expect(window.location.href).toBe('');
      expect(screen.getByRole('heading', { name: 'My Workspaces' })).toBeInTheDocument();
    });

    it('handles workspace settings while the user context has no memberships', async () => {
      vi.mocked(UserContext.useUser).mockReturnValue({ user: null, loading: false, error: null, signedOut: false, refetch: vi.fn(), logout: vi.fn() });
      renderWithRouter(['/settings?section=workspaces']);
      expect(screen.getByText('No active workspaces')).toBeInTheDocument();
      expect(await screen.findByText('No workspaces to restore')).toBeInTheDocument();
    });

    it('refreshes session metadata after a confirmed workspace deletion', async () => {
      const reload = vi.fn();
      const refetch = vi.fn().mockResolvedValue(undefined);
      vi.mocked(UserContext.useUser).mockReturnValue({ user: mockAdminUser, loading: false, error: null, signedOut: false, refetch, logout: vi.fn() });
      vi.stubGlobal('location', { href: '', reload });
      vi.spyOn(workspacesApi, 'getStats').mockResolvedValue({ workspaceId: 1, workspaceName: mockWorkspaceMembership.workspaceName,
        collectionCount: 2, categoryCount: 3, itemCount: 4, imageCount: 0, userCount: 1, adminCount: 1 });
      vi.spyOn(workspacesApi, 'deleteWorkspace').mockResolvedValue({ success: true });
      renderWithRouter(['/settings?section=workspaces']);
      await userEvent.click(screen.getByRole('button', { name: `Delete ${mockWorkspaceMembership.workspaceName}` }));
      const dialog = await screen.findByRole('dialog', { name: `Delete "${mockWorkspaceMembership.workspaceName}"` });
      expect(reload).not.toHaveBeenCalled();
      await userEvent.click(within(dialog).getByRole('checkbox'));
      await userEvent.click(within(dialog).getByRole('button', { name: 'Delete Workspace' }));
      await waitFor(() => expect(refetch).toHaveBeenCalledExactlyOnceWith({ throwOnError: true, endSessionIfAnonymous: true }));
      expect(reload).not.toHaveBeenCalled();
      expect(workspacesApi.deleteWorkspace).toHaveBeenCalledExactlyOnceWith(1);
    });
    it('should render the settings page with header', () => {
      renderWithRouter();

      expect(screen.getByText('Settings')).toBeInTheDocument();
      expect(screen.getByTestId('user-button')).toBeInTheDocument();
    });

    it('should load collections on mount', () => {
      renderWithRouter();

      expect(mockLoadCollections).toHaveBeenCalled();
    });

    it('should show all nav items for admin users', () => {
      renderWithRouter();

      // Check nav items by looking within the nav element
      const nav = screen.getByRole('navigation');
      expect(nav).toHaveTextContent('Collections');
      expect(nav).toHaveTextContent('Item Templates');
      expect(nav).toHaveTextContent('Team Members');
      expect(nav).toHaveTextContent('Data Export');
      expect(nav).toHaveTextContent('Support');
    });

    it('should show limited nav items for normal users', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: mockNormalUser,
        loading: false,
        error: null,
        signedOut: false, refetch: vi.fn(),
        logout: vi.fn(),
      });

      renderWithRouter();

      // Check nav items by looking within the nav element
      const nav = screen.getByRole('navigation');
      expect(nav).toHaveTextContent('Collections');
      expect(nav).not.toHaveTextContent('Item Templates');
      expect(nav).not.toHaveTextContent('Team Members');
      expect(nav).not.toHaveTextContent('Data Export');
      expect(nav).toHaveTextContent('Support');
    });

  });

  describe('section navigation', () => {
    it('protects navigation while a collection save is pending and releases it after failure', async () => {
      const user = userEvent.setup();
      const pending = deferred<void>();
      mockUpdateCollection.mockReturnValueOnce(pending.promise);
      const { router } = renderWithRouter();
      await user.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
      await user.type(screen.getByRole('textbox', { name: 'Name' }), ' revised');
      await user.click(screen.getByRole('button', { name: 'Save Changes' }));
      const nav = within(screen.getByRole('navigation', { name: 'Settings navigation' }));
      expect(nav.getByRole('button', { name: 'Support' })).toBeDisabled();
      await act(() => router.navigate('/settings?section=support'));
      expect(screen.getByRole('form', { name: 'Edit collection' })).toBeInTheDocument();
      expect(mockConfirm).not.toHaveBeenCalled();
      await act(async () => pending.reject(new Error('Save failed')));
      expect(nav.getByRole('button', { name: 'Support' })).toBeEnabled();
      await user.click(nav.getByRole('button', { name: 'Support' }));
      expect(mockConfirm).toHaveBeenCalledOnce();
    });

    it('handles collection and account sections without a user identity', async () => {
      const user = userEvent.setup();
      vi.mocked(UserContext.useUser).mockReturnValue({ ...UserContext.useUser(), user: null });
      renderWithRouter();
      expect(screen.queryByRole('button', { name: '+ New Collection' })).not.toBeInTheDocument();
      await user.click(screen.getByRole('button', { name: 'Account' }));
      expect(screen.getByText('Account deletion settings')).toBeInTheDocument();
    });

    it('keeps confirmed section changes in browser history and protects unsaved drafts when going back', async () => {
      const user = userEvent.setup();
      const { router } = renderWithRouter(['/settings?section=support']);
      await user.click(screen.getByRole('button', { name: 'Collections' }));
      await user.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
      await user.type(screen.getByPlaceholderText('My Collection'), ' revised');
      mockConfirm.mockReturnValue(false);
      await act(() => router.navigate(-1));
      expect(screen.getByPlaceholderText('My Collection')).toHaveValue('Test Collection 1 revised');
      expect(router.state.location.search).toBe('?section=collections');
      mockConfirm.mockReturnValue(true);
      await act(() => router.navigate(-1));
      expect(screen.getByTestId('support-section')).toBeInTheDocument();
      await act(() => router.navigate(1));
      expect(screen.queryByPlaceholderText('My Collection')).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Collections' })).toHaveAttribute('aria-current', 'page');
    });

    it('clears collection template and category sessions when leaving their section', async () => {
      const user = userEvent.setup();
      renderWithRouter();
      await user.click(screen.getAllByRole('button', { name: 'Templates' })[0]);
      await user.click(screen.getByRole('button', { name: 'Mark Collection Templates Dirty' }));
      await user.click(within(screen.getByRole('navigation', { name: 'Settings navigation' })).getByRole('button', { name: 'Support' }));
      await user.click(screen.getByRole('button', { name: 'Collections' }));
      expect(screen.queryByTestId('collection-template-editor')).not.toBeInTheDocument();
      await user.click(screen.getAllByRole('button', { name: 'Categories' })[0]);
      await user.click(within(screen.getByRole('navigation', { name: 'Settings navigation' })).getByRole('button', { name: 'Support' }));
      expect(screen.queryByTestId('category-manager-modal')).not.toBeInTheDocument();
      expect(mockConfirm).toHaveBeenCalledTimes(1);
    });

    it('uses normal router navigation for the return link and supports account deep links', async () => {
      const user = userEvent.setup();
      renderWithRouter(['/settings?section=account']);
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
      expect(screen.getByText('Account deletion settings')).toBeInTheDocument();
      await user.click(screen.getByRole('link', { name: 'Return to Collections' }));
      expect(screen.getByText('Collection overview')).toBeInTheDocument();
    });

    it('should default to dashboard section', () => {
      renderWithRouter(['/settings']);

      expect(screen.getByText(/Loading workspace statistics/)).toBeInTheDocument();
    });

    it('should switch to templates section', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      await user.click(screen.getByText('Item Templates'));

      expect(screen.getByTestId('item-template-editor')).toBeInTheDocument();
    });

    it('should switch to team section', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      await user.click(screen.getByText('Team Members'));

      expect(screen.getByTestId('user-management')).toBeInTheDocument();
    });

    it('should switch to export section', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      // Click on nav item
      const nav = screen.getByRole('navigation');
      await user.click(within(nav).getByText('Data Export'));

      expect(screen.getByText(/Download the active workspace’s collections/)).toBeInTheDocument();
    });

    it('should switch to support section', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      // Click on nav item (not header button)
      const nav = screen.getByRole('navigation');
      await user.click(within(nav).getByText('Support'));

      expect(screen.getByTestId('support-section')).toBeInTheDocument();
    });

    it('should warn when switching sections with unsaved changes', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      // Enter edit mode
      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);

      // Modify the name
      const nameInput = screen.getByDisplayValue('Test Collection 1');
      await user.clear(nameInput);
      await user.type(nameInput, 'Modified Name');

      // Try to switch sections via nav
      const nav = screen.getByRole('navigation');
      await user.click(within(nav).getByText('Support'));

      expect(mockConfirm).toHaveBeenCalledWith('You have unsaved changes. Discard them?');
    });

    it('should initialize from URL query param', () => {
      renderWithRouter(['/settings?section=support']);

      expect(screen.getByTestId('support-section')).toBeInTheDocument();
    });
  });

  describe('collections section - list view', () => {
    it('should display all collections', () => {
      renderWithRouter();

      expect(screen.getByText('Test Collection 1')).toBeInTheDocument();
      expect(screen.getByText('Test Collection 2')).toBeInTheDocument();
    });

    it('should display collection descriptions', () => {
      renderWithRouter();

      expect(screen.getByText('First collection description')).toBeInTheDocument();
      expect(screen.getByText('Second collection description')).toBeInTheDocument();
    });

    it('should display visibility status', () => {
      renderWithRouter();

      expect(screen.getByText('🌐 Public')).toBeInTheDocument();
      expect(screen.getByText('🔒 Private')).toBeInTheDocument();
    });

    it('should show New Collection button for admin users', () => {
      renderWithRouter();

      expect(screen.getByText('+ New Collection')).toBeInTheDocument();
    });

    it('should hide New Collection button for normal users', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: mockNormalUser,
        loading: false,
        error: null,
        signedOut: false, refetch: vi.fn(),
        logout: vi.fn(),
      });

      renderWithRouter();

      expect(screen.queryByText('+ New Collection')).not.toBeInTheDocument();
    });

    it('should show Delete button for admin users with multiple collections', () => {
      renderWithRouter();

      const deleteButtons = screen.getAllByText('Delete');
      expect(deleteButtons).toHaveLength(2);
    });

    it('should hide Delete button for normal users', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: mockNormalUser,
        loading: false,
        error: null,
        signedOut: false, refetch: vi.fn(),
        logout: vi.fn(),
      });

      renderWithRouter();

      expect(screen.queryByText('Delete')).not.toBeInTheDocument();
    });

    it('should hide Delete button when only one collection exists', () => {
      vi.mocked(DataContext.useCollectionsData).mockReturnValue(createMockDataContextValue({
        collections: [mockCollections[0]],
        addCollection: mockAddCollection,
        updateCollection: mockUpdateCollection,
        deleteCollection: mockDeleteCollection,
        loadCollections: mockLoadCollections,
      }));

      renderWithRouter();

      expect(screen.queryByText('Delete')).not.toBeInTheDocument();
    });
  });

  describe('collections section - setup wizard', () => {
    it('should show setup wizard when New Collection clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      await user.click(screen.getByText('+ New Collection'));

      expect(screen.getByTestId('collection-setup-wizard')).toBeInTheDocument();
    });

    it('should close wizard using the collection cache updated by setup', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      await user.click(screen.getByText('+ New Collection'));
      await user.click(screen.getByText('Complete Setup'));

      expect(screen.queryByTestId('collection-setup-wizard')).not.toBeInTheDocument();
      expect(mockLoadCollections).toHaveBeenCalledTimes(1); // Initial read; setup updates the shared cache
    });

    it('should close wizard on cancel', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      await user.click(screen.getByText('+ New Collection'));
      await user.click(screen.getByText('Cancel Setup'));

      expect(screen.queryByTestId('collection-setup-wizard')).not.toBeInTheDocument();
    });
  });

  describe('collections section - edit mode', () => {
    it('should enter edit mode when Edit clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);

      expect(screen.getByText('Edit Collection')).toBeInTheDocument();
      expect(screen.getByDisplayValue('Test Collection 1')).toBeInTheDocument();
    });

    it('should populate form with collection data', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);

      expect(screen.getByDisplayValue('Test Collection 1')).toBeInTheDocument();
      expect(screen.getByDisplayValue('First collection description')).toBeInTheDocument();
      expect(screen.getByDisplayValue('https://example.com/hero1.jpg')).toBeInTheDocument();
    });

    it('should show Manage Templates button in edit mode', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);

      expect(screen.getByText('Manage Templates')).toBeInTheDocument();
    });

    it('should open collection template editor when Manage Templates clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);
      await user.click(screen.getByText('Manage Templates'));

      expect(screen.getByTestId('collection-template-editor')).toBeInTheDocument();
      expect(screen.getByText('Editing templates for: Test Collection 1')).toBeInTheDocument();
    });

    it('should save changes when form submitted', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);

      const nameInput = screen.getByDisplayValue('Test Collection 1');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Collection Name');

      await user.click(screen.getByText('Save Changes'));

      expect(mockUpdateCollection).toHaveBeenCalledWith(1, expect.objectContaining({
        name: 'Updated Collection Name',
      }));
    });

    it('should show error when name is empty', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);

      const nameInput = screen.getByDisplayValue('Test Collection 1');
      await user.clear(nameInput);

      await user.click(screen.getByText('Save Changes'));

      expect(screen.getByText('Name is required')).toBeInTheDocument();
      expect(mockUpdateCollection).not.toHaveBeenCalled();
    });

    it('should show error when update fails', async () => {
      mockUpdateCollection.mockRejectedValue(new Error('Update failed'));
      const user = userEvent.setup();
      renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);

      await user.click(screen.getByText('Save Changes'));

      await waitFor(() => {
        expect(screen.getByText('Update failed')).toBeInTheDocument();
      });
    });

    it('should cancel edit and return to list', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);

      // Find the form and get its Cancel button within
      const form = screen.getByRole('form', { name: 'Edit collection' });
      expect(form).toBeInTheDocument();
      const formCancelButton = within(form as HTMLElement).getByText('Cancel');
      await user.click(formCancelButton);

      expect(screen.queryByText('Edit Collection')).not.toBeInTheDocument();
      expect(screen.getByText('Test Collection 1')).toBeInTheDocument();
    });

    it('should show Unpublish Collection button when editing a public collection', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);

      expect(screen.getByText('Unpublish Collection')).toBeInTheDocument();
      expect(screen.queryByText('Publish Collection')).not.toBeInTheDocument();
    });

    it('should show Publish Collection button when editing a private collection', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[1]);

      expect(screen.getByText('Publish Collection')).toBeInTheDocument();
      expect(screen.queryByText('Unpublish Collection')).not.toBeInTheDocument();
    });

    it('should call requestUnpublish when clicking Unpublish Collection', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);
      await user.click(screen.getByText('Unpublish Collection'));

      expect(mockRequestUnpublish).toHaveBeenCalledWith([{ type: 'collection', id: 1 }]);
    });

    it('should call requestPublish when clicking Publish Collection', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[1]);
      await user.click(screen.getByText('Publish Collection'));

      expect(mockRequestPublish).toHaveBeenCalledWith([{ type: 'collection', id: 2 }]);
    });

    it('should warn when canceling with unsaved changes', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);

      const nameInput = screen.getByDisplayValue('Test Collection 1');
      await user.clear(nameInput);
      await user.type(nameInput, 'Modified Name');

      // Find the form and get its Cancel button within
      const form = screen.getByRole('form', { name: 'Edit collection' });
      expect(form).toBeInTheDocument();
      const formCancelButton = within(form as HTMLElement).getByText('Cancel');
      await user.click(formCancelButton);

      expect(mockConfirm).toHaveBeenCalledWith('You have unsaved changes. Discard them?');
    });
  });

  describe('collections section - delete', () => {
    it('should show confirmation dialog before delete', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const deleteButtons = screen.getAllByText('Delete');
      await user.click(deleteButtons[0]);

      expect(mockConfirm).toHaveBeenCalledWith(
        'Delete "Test Collection 1"? All items and categories within it will be permanently deleted.'
      );
    });

    it('should delete collection when confirmed', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const deleteButtons = screen.getAllByText('Delete');
      await user.click(deleteButtons[0]);

      expect(mockDeleteCollection).toHaveBeenCalledWith(1);
    });

    it('should not delete when confirmation cancelled', async () => {
      mockConfirm.mockReturnValue(false);
      const user = userEvent.setup();
      renderWithRouter();

      const deleteButtons = screen.getAllByText('Delete');
      await user.click(deleteButtons[0]);

      expect(mockDeleteCollection).not.toHaveBeenCalled();
    });

    it('should rely on the collection cache after delete', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const deleteButtons = screen.getAllByText('Delete');
      await user.click(deleteButtons[0]);

      await waitFor(() => {
        expect(mockLoadCollections).toHaveBeenCalledTimes(1); // Initial read; deletion updates the shared cache
      });
    });

    it('should show error when delete fails', async () => {
      mockDeleteCollection.mockRejectedValue(new Error('Delete failed'));
      const user = userEvent.setup();
      renderWithRouter();

      const deleteButtons = screen.getAllByText('Delete');
      await user.click(deleteButtons[0]);

      await waitFor(() => {
        expect(screen.getByText('Delete failed')).toBeInTheDocument();
      });
    });
  });

  describe('collections section - template editor', () => {
    it('should open collection template editor from card', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const templateButtons = screen.getAllByText('Templates');
      await user.click(templateButtons[0]);

      expect(screen.getByTestId('collection-template-editor')).toBeInTheDocument();
    });

    it('should close collection template editor', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const templateButtons = screen.getAllByText('Templates');
      await user.click(templateButtons[0]);
      await user.click(screen.getByText('Close Collection Templates'));

      expect(screen.queryByTestId('collection-template-editor')).not.toBeInTheDocument();
    });
  });

  describe('collections section - category manager', () => {
    it('should open CategoryManagerModal from collection card Categories button', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const categoriesButtons = screen.getAllByText('Categories');
      await user.click(categoriesButtons[0]);

      expect(screen.getByTestId('category-manager-modal')).toBeInTheDocument();
    });

    it('should pass correct collectionId to CategoryManagerModal', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const categoriesButtons = screen.getAllByText('Categories');
      await user.click(categoriesButtons[0]);

      expect(screen.getByTestId('category-manager-modal')).toHaveAttribute('data-collection-id', '1');
    });

    it('should close CategoryManagerModal', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const categoriesButtons = screen.getAllByText('Categories');
      await user.click(categoriesButtons[0]);
      expect(screen.getByTestId('category-manager-modal')).toBeInTheDocument();

      await user.click(screen.getByText('Close Category Manager'));
      expect(screen.queryByTestId('category-manager-modal')).not.toBeInTheDocument();
    });
  });

  describe('templates section', () => {
    it('blocks section and history navigation while a template write is pending', async () => {
      const { router } = renderWithRouter(['/settings?section=templates']);
      await userEvent.click(screen.getByRole('button', { name: 'Saving template' }));
      expect(within(screen.getByRole('navigation')).getByRole('button', { name: /Support/ })).toBeDisabled();
      await act(async () => { await router.navigate('/settings?section=collections'); });
      expect(router.state.location.search).toBe('?section=templates');
      expect(mockConfirm).not.toHaveBeenCalled();
      await userEvent.click(screen.getByRole('button', { name: 'Template saved' }));
      await userEvent.click(screen.getByRole('button', { name: /Collections/ }));
      expect(router.state.location.search).toBe('?section=collections');
      expect(mockConfirm).not.toHaveBeenCalled();
    });
    it('returns from the template library to collection settings', async () => {
      const user = userEvent.setup();
      const { router } = renderWithRouter(['/settings?section=templates']);
      await user.click(screen.getByRole('button', { name: 'Close Template Editor' }));
      expect(router.state.location.search).toBe('?section=collections');
      expect(screen.getByRole('article', { name: 'Test Collection 1' })).toBeInTheDocument();
    });

    it('should render item template editor', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      await user.click(screen.getByText('Item Templates'));

      expect(screen.getByTestId('item-template-editor')).toBeInTheDocument();
    });

    it('should track dirty state from template editor', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const nav = screen.getByRole('navigation');
      await user.click(within(nav).getByText('Item Templates'));
      await user.click(screen.getByText('Mark Dirty'));

      // Now try to switch sections - should warn about unsaved changes
      await user.click(within(nav).getByText('Support'));

      expect(mockConfirm).toHaveBeenCalledWith('You have unsaved changes. Discard them?');
    });
  });

  describe('team section', () => {
    it('keeps navigation in the team section until a pending action finishes', async () => {
      const user = userEvent.setup();
      renderWithRouter();
      const nav = screen.getByRole('navigation');
      await user.click(within(nav).getByText('Team Members'));
      await user.click(screen.getByText('Saving team change'));
      await user.click(within(nav).getByText('Support'));
      expect(screen.getByTestId('user-management')).toBeInTheDocument();
      expect(mockConfirm).not.toHaveBeenCalled();
      await user.click(screen.getByText('Team change saved'));
      await user.click(within(nav).getByText('Support'));
      expect(screen.getByTestId('support-section')).toBeInTheDocument();
    });
    it('should render user management component', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const nav = screen.getByRole('navigation');
      await user.click(within(nav).getByText('Team Members'));

      expect(screen.getByTestId('user-management')).toBeInTheDocument();
      expect(screen.getByText(/Invite team members to collaborate/)).toBeInTheDocument();
    });

    it('should track dirty state from team management', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const nav = screen.getByRole('navigation');
      await user.click(within(nav).getByText('Team Members'));
      await user.click(screen.getByText('Mark Team Dirty'));

      // Now try to switch sections - should warn about unsaved changes
      await user.click(within(nav).getByText('Support'));

      expect(mockConfirm).toHaveBeenCalledWith('You have unsaved changes. Discard them?');
    });
  });

  describe('export section', () => {
    it('should render export section', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      await user.click(screen.getByText('Data Export'));

      expect(screen.getByText('Export All Data')).toBeInTheDocument();
      expect(screen.getByText('Download Export')).toBeInTheDocument();
    });

    it('should trigger export when button clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      await user.click(screen.getByText('Data Export'));
      await user.click(screen.getByText('Download Export'));

      expect(exportApiModule.exportApi.downloadExport).toHaveBeenCalled();
    });

    it('should show loading state during export', async () => {
      vi.mocked(exportApiModule.exportApi.downloadExport).mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve({ blob: new Blob(), filename: 'test.zip' }), 100))
      );

      const user = userEvent.setup();
      renderWithRouter();

      await user.click(screen.getByText('Data Export'));
      await user.click(screen.getByText('Download Export'));

      expect(screen.getByText('Exporting...')).toBeInTheDocument();
    });

    it('should show error when export fails', async () => {
      vi.mocked(exportApiModule.exportApi.downloadExport).mockRejectedValue(new Error('Export failed'));

      const user = userEvent.setup();
      renderWithRouter();

      await user.click(screen.getByText('Data Export'));
      await user.click(screen.getByText('Download Export'));

      await waitFor(() => {
        expect(screen.getByText('Export failed')).toBeInTheDocument();
      });
    });
  });

  describe('support section', () => {
    it('guards support drafts and blocks route changes until a support mutation finishes', async () => {
      const user = userEvent.setup();
      const { router } = renderWithRouter(['/settings?section=support']);
      await user.click(screen.getByRole('button', { name: 'Draft support reply' }));
      mockConfirm.mockReturnValueOnce(false);
      await user.click(screen.getByRole('button', { name: 'Dashboard' }));
      expect(router.state.location.search).toBe('?section=support');
      await user.click(screen.getByRole('button', { name: 'Sending support reply' }));
      expect(screen.getByRole('button', { name: 'Dashboard' })).toBeDisabled();
      await act(() => router.navigate('/collections'));
      expect(router.state.location.pathname).toBe('/settings');
      await user.click(screen.getByRole('button', { name: 'Support reply sent' }));
      await user.click(screen.getByRole('button', { name: 'Dashboard' }));
      expect(router.state.location.search).toBe('?section=dashboard');
    });
    it('should render support section', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const nav = screen.getByRole('navigation');
      await user.click(within(nav).getByText('Support'));

      expect(screen.getByTestId('support-section')).toBeInTheDocument();
      expect(screen.getByText('Support Requests')).toBeInTheDocument();
    });
  });

  describe('support modal', () => {
    it('opens a new request from the section and refreshes the list after success', async () => {
      const user = userEvent.setup();
      renderWithRouter(['/settings?section=support']);
      await user.click(screen.getByRole('button', { name: 'New support request' }));
      await user.click(screen.getByRole('button', { name: 'Send support request' }));
      expect(screen.getByTestId('support-section')).toHaveAttribute('data-refresh', '1');
    });
    it('should open support modal from header', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      // The header has a support link button with aria-label="Support"
      const supportLink = within(screen.getByTestId('site-header')).getByRole('button', { name: 'Support' });
      await user.click(supportLink);

      expect(screen.getByTestId('support-modal')).toBeInTheDocument();
    });

    it('should close support modal', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      // Open modal using the header support button
      const supportLink = within(screen.getByTestId('site-header')).getByRole('button', { name: 'Support' });
      await user.click(supportLink);

      // Close modal
      await user.click(screen.getByText('Close Support Modal'));

      expect(screen.queryByTestId('support-modal')).not.toBeInTheDocument();
    });
  });

  describe('snapshots', () => {
    it('should match snapshot for admin user - collections section', () => {
      const { container } = renderWithRouter();

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot for normal user - collections section', () => {
      vi.mocked(UserContext.useUser).mockReturnValue({
        user: mockNormalUser,
        loading: false,
        error: null,
        signedOut: false, refetch: vi.fn(),
        logout: vi.fn(),
      });

      const { container } = renderWithRouter();

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot for templates section', async () => {
      const user = userEvent.setup();
      const { container } = renderWithRouter();

      await user.click(screen.getByText('Item Templates'));

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot for team section', async () => {
      const user = userEvent.setup();
      const { container } = renderWithRouter();

      await user.click(screen.getByText('Team Members'));

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot for export section', async () => {
      const user = userEvent.setup();
      const { container } = renderWithRouter();

      await user.click(screen.getByText('Data Export'));

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot for support section', async () => {
      const user = userEvent.setup();
      const { container } = renderWithRouter();

      const nav = screen.getByRole('navigation');
      await user.click(within(nav).getByText('Support'));

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot in collection edit mode', async () => {
      const user = userEvent.setup();
      const { container } = renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot with setup wizard', async () => {
      const user = userEvent.setup();
      const { container } = renderWithRouter();

      await user.click(screen.getByText('+ New Collection'));

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot with collection template editor', async () => {
      const user = userEvent.setup();
      const { container } = renderWithRouter();

      const templateButtons = screen.getAllByText('Templates');
      await user.click(templateButtons[0]);

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot with error displayed', async () => {
      mockUpdateCollection.mockRejectedValue(new Error('Failed to save'));
      const user = userEvent.setup();
      const { container } = renderWithRouter();

      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);
      await user.click(screen.getByText('Save Changes'));

      await waitFor(() => {
        expect(screen.getByText('Failed to save')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Dashboard' })).toBeEnabled();
      });

      expect(container).toMatchSnapshot();
    });
  });
});
