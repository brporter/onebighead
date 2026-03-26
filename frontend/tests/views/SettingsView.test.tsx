import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import SettingsView from '../../src/views/SettingsView';
import * as UserContext from '../../src/contexts/useUser';
import * as DataContext from '../../src/contexts/useData';
import * as exportApiModule from '../../src/api/export';
import { WorkspaceRole, Visibility } from '../../src/utils/types';
import type { Collection } from '../../src/utils/types';
import { createMockDataContextValue } from '../testUtils';

// Mock the contexts
vi.mock('../../src/contexts/useUser', () => ({
  useUser: vi.fn(),
}));

vi.mock('../../src/contexts/useData', () => ({
  useData: vi.fn(),
}));

// Mock the export API
vi.mock('../../src/api/export', () => ({
  exportApi: {
    downloadExport: vi.fn(),
  },
}));

// Mock child components to simplify testing
vi.mock('../../src/components/template/ItemTemplateEditor', () => ({
  default: ({ onClose, onDirtyChange }: { onClose: () => void; onDirtyChange: (dirty: boolean) => void }) => (
    <div data-testid="item-template-editor">
      <button onClick={onClose}>Close Template Editor</button>
      <button onClick={() => onDirtyChange(true)}>Mark Dirty</button>
    </div>
  ),
}));

vi.mock('../../src/components/collection/CollectionTemplateEditor', () => ({
  default: ({ collection, onClose, onDirtyChange }: { collection: Collection; onClose: () => void; onDirtyChange: (dirty: boolean) => void }) => (
    <div data-testid="collection-template-editor">
      <span>Editing templates for: {collection.name}</span>
      <button onClick={onClose}>Close Collection Templates</button>
      <button onClick={() => onDirtyChange(true)}>Mark Collection Templates Dirty</button>
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
  SupportSection: ({ isFullPage }: { isFullPage: boolean }) => (
    <div data-testid="support-section">Support Section (fullPage: {isFullPage.toString()})</div>
  ),
}));

// Mock the barrel export for user components
vi.mock('../../src/components/user', () => ({
  UserButton: () => <button data-testid="user-button">User Button</button>,
  UserManagement: ({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) => (
    <div data-testid="user-management">
      <span>User Management</span>
      <button onClick={() => onDirtyChange?.(true)}>Mark Team Dirty</button>
    </div>
  ),
}));

vi.mock('../../src/components/support/SupportModal', () => ({
  SupportModal: ({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) =>
    isOpen ? (
      <div data-testid="support-modal">
        <button onClick={onClose}>Close Support Modal</button>
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

// Mock navigate
const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

describe('SettingsView', () => {
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
    return render(
      <MemoryRouter initialEntries={initialEntries}>
        <SettingsView />
      </MemoryRouter>
    );
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockConfirm.mockReturnValue(true);

    vi.mocked(UserContext.useUser).mockReturnValue({
      user: mockAdminUser,
      loading: false,
      error: null,
      refetch: vi.fn(),
      logout: vi.fn(),
    });

    vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
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
    it('should render the settings page with header', () => {
      renderWithRouter();

      expect(screen.getByText('Settings')).toBeInTheDocument();
      expect(screen.getByText('Back to Collections →')).toBeInTheDocument();
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
        refetch: vi.fn(),
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

    it('should navigate back to collections when back button clicked', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      await user.click(screen.getByText('Back to Collections →'));

      expect(mockNavigate).toHaveBeenCalledWith('/collections');
    });

    it('should show confirm dialog when navigating with unsaved changes', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      // Click edit on a collection to enter edit mode
      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);

      // Modify the name
      const nameInput = screen.getByDisplayValue('Test Collection 1');
      await user.clear(nameInput);
      await user.type(nameInput, 'Modified Name');

      // Try to navigate back
      await user.click(screen.getByText('Back to Collections →'));

      expect(mockConfirm).toHaveBeenCalledWith('You have unsaved changes. Discard them?');
    });

    it('should not navigate when user cancels confirm dialog', async () => {
      mockConfirm.mockReturnValue(false);
      const user = userEvent.setup();
      renderWithRouter();

      // Enter edit mode and modify
      const editButtons = screen.getAllByText('Edit');
      await user.click(editButtons[0]);
      const nameInput = screen.getByDisplayValue('Test Collection 1');
      await user.clear(nameInput);
      await user.type(nameInput, 'Modified Name');

      // Try to navigate back
      await user.click(screen.getByText('Back to Collections →'));

      expect(mockNavigate).not.toHaveBeenCalled();
    });
  });

  describe('section navigation', () => {
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

      expect(screen.getByText(/Download all your collections, categories, and items as a ZIP file/)).toBeInTheDocument();
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
        refetch: vi.fn(),
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
        refetch: vi.fn(),
        logout: vi.fn(),
      });

      renderWithRouter();

      expect(screen.queryByText('Delete')).not.toBeInTheDocument();
    });

    it('should hide Delete button when only one collection exists', () => {
      vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
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

    it('should close wizard and reload collections on complete', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      await user.click(screen.getByText('+ New Collection'));
      await user.click(screen.getByText('Complete Setup'));

      expect(screen.queryByTestId('collection-setup-wizard')).not.toBeInTheDocument();
      expect(mockLoadCollections).toHaveBeenCalledTimes(2); // Initial + after complete
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
      const form = document.querySelector('.settings-form');
      expect(form).toBeInTheDocument();
      const formCancelButton = within(form as HTMLElement).getByText('Cancel');
      await user.click(formCancelButton);

      expect(screen.queryByText('Edit Collection')).not.toBeInTheDocument();
      expect(screen.getByText('Test Collection 1')).toBeInTheDocument();
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
      const form = document.querySelector('.settings-form');
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
        'Are you sure you want to delete this collection? All items and categories within it will be permanently deleted.'
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

    it('should reload collections after delete', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const deleteButtons = screen.getAllByText('Delete');
      await user.click(deleteButtons[0]);

      await waitFor(() => {
        expect(mockLoadCollections).toHaveBeenCalledTimes(2); // Initial + after delete
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
    it('should open support modal from header', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      // The header has a support link button with aria-label="Support"
      const supportLink = screen.getByRole('button', { name: 'Support' });
      await user.click(supportLink);

      expect(screen.getByTestId('support-modal')).toBeInTheDocument();
    });

    it('should close support modal', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      // Open modal using the header support button
      const supportLink = screen.getByRole('button', { name: 'Support' });
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
        refetch: vi.fn(),
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
      });

      expect(container).toMatchSnapshot();
    });
  });
});
