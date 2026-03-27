import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CategoryManagerModal from '../src/components/category/CategoryManagerModal';
import type { Category } from '../src/utils/types';

// Use vi.hoisted for mocks that need to be available before module loading
const {
  mockLoadCategoriesForCollection,
  mockAddCategory,
  mockUpdateCategory,
  mockDeleteCategory,
  mockReorderCategories,
  mockPublishCategory,
  mockUnpublishCategory,
  mockGetUnpublishCategoryPreview,
  mockShowToast,
  mockCategories,
} = vi.hoisted(() => {
  const cats: Category[] = [
    {
      workspaceId: 1,
      collectionId: 1,
      categoryId: 1,
      name: 'Bravo',
      description: 'Description 1',
      parentCategoryId: null,
      isSystem: false,
      visibility: 'Private' as const,
      effectiveIsPublic: false,
      itemTemplateIds: [],
      sortOrder: 0,
    },
    {
      workspaceId: 1,
      collectionId: 1,
      categoryId: 2,
      name: 'Alpha',
      description: 'Description 2',
      parentCategoryId: null,
      isSystem: false,
      visibility: 'Private' as const,
      effectiveIsPublic: false,
      itemTemplateIds: [],
      sortOrder: 1,
    },
    {
      workspaceId: 1,
      collectionId: 1,
      categoryId: 3,
      name: 'Child of Bravo',
      description: 'Description 3',
      parentCategoryId: 1,
      isSystem: false,
      visibility: 'Public' as const,
      effectiveIsPublic: true,
      itemTemplateIds: [],
      sortOrder: 0,
    },
    {
      workspaceId: 1,
      collectionId: 1,
      categoryId: 99,
      name: 'Unassigned Items',
      description: 'System category',
      parentCategoryId: null,
      isSystem: true,
      visibility: 'Private' as const,
      effectiveIsPublic: false,
      itemTemplateIds: [],
      sortOrder: 999,
    },
  ];

  return {
    mockLoadCategoriesForCollection: vi.fn(),
    mockAddCategory: vi.fn(),
    mockUpdateCategory: vi.fn(),
    mockDeleteCategory: vi.fn(),
    mockReorderCategories: vi.fn(),
    mockPublishCategory: vi.fn(),
    mockUnpublishCategory: vi.fn(),
    mockGetUnpublishCategoryPreview: vi.fn(),
    mockShowToast: vi.fn(),
    mockCategories: cats,
  };
});

// Mock DataContext
vi.mock('../src/contexts/useData', () => ({
  useData: () => ({
    categories: mockCategories,
    loadCategoriesForCollection: mockLoadCategoriesForCollection,
    addCategory: mockAddCategory,
    updateCategory: mockUpdateCategory,
    deleteCategory: mockDeleteCategory,
    reorderCategories: mockReorderCategories,
    publishCategory: mockPublishCategory,
    unpublishCategory: mockUnpublishCategory,
    getUnpublishCategoryPreview: mockGetUnpublishCategoryPreview,
  }),
}));

// Mock useToast
vi.mock('../src/contexts/useToast', () => ({
  useToast: () => ({
    showToast: mockShowToast,
  }),
}));

// Track props passed to child components
let lastTreeProps: Record<string, unknown> = {};
let lastFormProps: Record<string, unknown> = {};

// Mock CategoryManagerTree
vi.mock('../src/components/category/CategoryManagerTree', () => ({
  default: (props: Record<string, unknown>) => {
    lastTreeProps = props;
    return (
      <div data-testid="category-manager-tree">
        <button data-testid="tree-select-1" onClick={() => (props.onSelect as (id: number) => void)(1)}>Select 1</button>
        <button data-testid="tree-select-2" onClick={() => (props.onSelect as (id: number) => void)(2)}>Select 2</button>
        <button data-testid="tree-add" onClick={props.onAdd as () => void}>Add</button>
        <button data-testid="tree-reorder" onClick={() => (props.onReorder as (u: { categoryId: number; sortOrder: number }[]) => void)([{ categoryId: 1, sortOrder: 0 }, { categoryId: 2, sortOrder: 1 }])}>Reorder</button>
        <button data-testid="tree-reparent" onClick={() => (props.onReparent as (id: number, parentId: number | null) => void)(3, 2)}>Reparent</button>
      </div>
    );
  },
}));

// Mock CategoryManagerForm
vi.mock('../src/components/category/CategoryManagerForm', () => ({
  default: (props: Record<string, unknown>) => {
    lastFormProps = props;
    // Wire up the formRef so the modal can call submit()
    const formRef = props.formRef as React.RefObject<{ submit: () => void } | null> | undefined;
    if (formRef && 'current' in formRef) {
      (formRef as React.MutableRefObject<{ submit: () => void } | null>).current = {
        submit: () => (props.onSave as (u: { name: string; description: string; parentCategoryId: number | null; itemTemplateIds: number[] }) => void)({ name: 'Updated', description: 'Desc', parentCategoryId: null, itemTemplateIds: [] }),
      };
    }
    return (
      <div data-testid="category-manager-form">
        <button data-testid="form-save" onClick={() => (props.onSave as (u: { name: string; description: string; parentCategoryId: number | null; itemTemplateIds: number[] }) => void)({ name: 'Updated', description: 'Desc', parentCategoryId: null, itemTemplateIds: [] })}>Save</button>
        <button data-testid="form-publish" onClick={() => (props.onPublish as (c: Category) => void)(mockCategories[0])}>Publish</button>
        <button data-testid="form-unpublish" onClick={() => (props.onUnpublish as (c: Category) => void)(mockCategories[2])}>Unpublish</button>
      </div>
    );
  },
}));

// Mock PublishConfirmModal
vi.mock('../src/components/common/PublishConfirmModal', () => ({
  PublishConfirmModal: (props: { onConfirm: (includeChildren: boolean) => void; onCancel: () => void }) => (
    <div data-testid="publish-confirm-modal">
      <button data-testid="publish-with-children" onClick={() => props.onConfirm(true)}>Publish with children</button>
      <button data-testid="publish-only" onClick={() => props.onConfirm(false)}>Publish only</button>
      <button data-testid="publish-cancel" onClick={props.onCancel}>Cancel Publish</button>
    </div>
  ),
}));

// Mock UnpublishConfirmModal
vi.mock('../src/components/common/UnpublishConfirmModal', () => ({
  UnpublishConfirmModal: (props: { onConfirm: () => void; onCancel: () => void }) => (
    <div data-testid="unpublish-confirm-modal">
      <button data-testid="unpublish-confirm" onClick={props.onConfirm}>Confirm Unpublish</button>
      <button data-testid="unpublish-cancel" onClick={props.onCancel}>Cancel Unpublish</button>
    </div>
  ),
}));

// Mock SlugSetupModal
vi.mock('../src/components/common/SlugSetupModal', () => ({
  SlugSetupModal: (props: { onConfirm: (slug: string) => void; onCancel: () => void }) => (
    <div data-testid="slug-setup-modal">
      <button data-testid="slug-confirm" onClick={() => props.onConfirm('my-slug')}>Confirm Slug</button>
      <button data-testid="slug-cancel" onClick={props.onCancel}>Cancel Slug</button>
    </div>
  ),
}));

// Mock publish toast utils
vi.mock('../src/utils/publishToastUtils', () => ({
  buildPublishToastMessage: vi.fn(() => 'Published!'),
  buildPublishToastDetails: vi.fn(() => undefined),
  buildUnpublishToastMessage: vi.fn(() => 'Unpublished!'),
}));

describe('CategoryManagerModal', () => {
  const defaultProps = {
    collectionId: 1,
    isOpen: true,
    onClose: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    lastTreeProps = {};
    lastFormProps = {};
    // Mock dialog methods
    HTMLDialogElement.prototype.showModal = vi.fn(function (this: HTMLDialogElement) {
      this.setAttribute('open', '');
    });
    HTMLDialogElement.prototype.close = vi.fn(function (this: HTMLDialogElement) {
      this.removeAttribute('open');
    });
    mockLoadCategoriesForCollection.mockResolvedValue(undefined);
    mockAddCategory.mockResolvedValue(100);
    mockUpdateCategory.mockResolvedValue(undefined);
    mockDeleteCategory.mockResolvedValue(undefined);
    mockReorderCategories.mockResolvedValue(undefined);
    mockPublishCategory.mockResolvedValue({ published: { type: 'category', id: 1, name: 'Bravo' }, promoted: [], childrenPublished: 0, requiresSlugSetup: false });
    mockUnpublishCategory.mockResolvedValue({ unpublished: { type: 'category', id: 3, name: 'Child of Bravo' } });
    mockGetUnpublishCategoryPreview.mockResolvedValue({ affectedPublicItems: 2, affectedPublicCategories: 0 });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('rendering', () => {
    it('should not render dialog content when isOpen is false', () => {
      render(<CategoryManagerModal {...defaultProps} isOpen={false} />);

      expect(HTMLDialogElement.prototype.close).toHaveBeenCalled();
      expect(HTMLDialogElement.prototype.showModal).not.toHaveBeenCalled();
    });

    it('should render modal with tree and form when isOpen is true', () => {
      render(<CategoryManagerModal {...defaultProps} />);

      expect(screen.getByText('Category Manager')).toBeInTheDocument();
      expect(screen.getByTestId('category-manager-tree')).toBeInTheDocument();
      expect(screen.getByTestId('category-manager-form')).toBeInTheDocument();
    });

    it('should call showModal when isOpen is true', () => {
      render(<CategoryManagerModal {...defaultProps} />);

      expect(HTMLDialogElement.prototype.showModal).toHaveBeenCalled();
    });
  });

  describe('loading categories', () => {
    it('should load categories on open', async () => {
      render(<CategoryManagerModal {...defaultProps} />);

      await waitFor(() => {
        expect(mockLoadCategoriesForCollection).toHaveBeenCalledWith(1);
      });
    });

    it('should not load categories when closed', () => {
      render(<CategoryManagerModal {...defaultProps} isOpen={false} />);

      expect(mockLoadCategoriesForCollection).not.toHaveBeenCalled();
    });
  });

  describe('selecting a category', () => {
    it('should pass selectedCategoryId to tree and category to form on select', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));

      expect(lastTreeProps.selectedCategoryId).toBe(1);
      expect((lastFormProps.category as Category)?.categoryId).toBe(1);
      expect(lastFormProps.isNew).toBe(false);
    });
  });

  describe('saving a category (update)', () => {
    it('should call updateCategory and refresh tree when saving existing category', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      // Select a category first
      await user.click(screen.getByTestId('tree-select-1'));
      // Save it
      await user.click(screen.getByTestId('form-save'));

      await waitFor(() => {
        expect(mockUpdateCategory).toHaveBeenCalledWith(1, { name: 'Updated', description: 'Desc', parentCategoryId: null, itemTemplateIds: [] });
      });
      await waitFor(() => {
        expect(mockLoadCategoriesForCollection).toHaveBeenCalledWith(1);
      });
    });

    it('should call addCategory when saving in create mode', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      // Switch to create mode
      await user.click(screen.getByTestId('tree-add'));
      // Save
      await user.click(screen.getByTestId('form-save'));

      await waitFor(() => {
        expect(mockAddCategory).toHaveBeenCalledWith({
          collectionId: 1,
          name: 'Updated',
          description: 'Desc',
          parentCategoryId: null,
          itemTemplateIds: [],
        });
      });
    });
  });

  describe('adding a new category', () => {
    it('should switch form to create mode when add clicked', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      // First select a category
      await user.click(screen.getByTestId('tree-select-1'));
      expect(lastFormProps.isNew).toBe(false);

      // Click add
      await user.click(screen.getByTestId('tree-add'));

      expect(lastFormProps.isNew).toBe(true);
      expect(lastTreeProps.selectedCategoryId).toBeNull();
    });
  });

  describe('deleting a category', () => {
    it('should call deleteCategory and clear selection', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      // Select a category first
      await user.click(screen.getByTestId('tree-select-1'));
      // Click the Delete button in the modal footer
      const deleteButton = screen.getByRole('button', { name: 'Delete' });
      await user.click(deleteButton);

      // Confirm in the delete confirmation modal
      const confirmButtons = screen.getAllByRole('button', { name: 'Delete' });
      // The confirmation modal's Delete button (last one)
      await user.click(confirmButtons[confirmButtons.length - 1]);

      await waitFor(() => {
        expect(mockDeleteCategory).toHaveBeenCalledWith(1);
      });
      await waitFor(() => {
        expect(lastTreeProps.selectedCategoryId).toBeNull();
      });
    });

    it('should not call deleteCategory when confirm is cancelled', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      // Click the Delete button in the modal footer
      const deleteButton = screen.getByRole('button', { name: 'Delete' });
      await user.click(deleteButton);

      // Click Cancel in the confirmation modal
      const cancelButtons = screen.getAllByRole('button', { name: 'Cancel' });
      await user.click(cancelButtons[cancelButtons.length - 1]);

      expect(mockDeleteCategory).not.toHaveBeenCalled();
    });
  });

  describe('reordering categories', () => {
    it('should call reorderCategories on reorder', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-reorder'));

      await waitFor(() => {
        expect(mockReorderCategories).toHaveBeenCalledWith([
          { categoryId: 1, sortOrder: 0 },
          { categoryId: 2, sortOrder: 1 },
        ]);
      });
    });
  });

  describe('reparenting categories', () => {
    it('should call updateCategory with new parentCategoryId and then reorderCategories', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-reparent'));

      await waitFor(() => {
        expect(mockUpdateCategory).toHaveBeenCalledWith(3, expect.objectContaining({ parentCategoryId: 2 }));
      });
      await waitFor(() => {
        expect(mockReorderCategories).toHaveBeenCalled();
      });
    });

    it('should compute sort orders including existing siblings in target parent', async () => {
      // Add a category with parentCategoryId=2 to have existing siblings
      const extraCat: Category = {
        workspaceId: 1,
        collectionId: 1,
        categoryId: 5,
        name: 'Existing Child of Alpha',
        description: '',
        parentCategoryId: 2,
        isSystem: false,
        visibility: 'Private' as const,
        effectiveIsPublic: false,
        itemTemplateIds: [],
        sortOrder: 0,
      };
      mockCategories.push(extraCat);

      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      // Reparent category 3 to parent 2 (which now has existing child 5)
      await user.click(screen.getByTestId('tree-reparent'));

      await waitFor(() => {
        expect(mockReorderCategories).toHaveBeenCalled();
      });

      // Verify that sibling 5 and reparented 3 both got sort orders
      const reorderCall = mockReorderCategories.mock.calls[0][0] as { categoryId: number; sortOrder: number }[];
      expect(reorderCall.find((c: { categoryId: number }) => c.categoryId === 5)).toBeDefined();
      expect(reorderCall.find((c: { categoryId: number }) => c.categoryId === 3)).toBeDefined();

      // Clean up
      mockCategories.pop();
    });
  });

  describe('publishing a category', () => {
    it('should show publish confirm modal and call publishCategory on confirm', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-publish'));

      // Publish confirm modal should appear
      expect(screen.getByTestId('publish-confirm-modal')).toBeInTheDocument();

      await user.click(screen.getByTestId('publish-with-children'));

      await waitFor(() => {
        expect(mockPublishCategory).toHaveBeenCalledWith(1, true);
      });
    });

    it('should show slug setup modal when publish requires slug setup', async () => {
      const user = userEvent.setup();
      mockPublishCategory.mockResolvedValue({
        published: { type: 'category', id: 1, name: 'Bravo' },
        promoted: [],
        childrenPublished: 0,
        requiresSlugSetup: true,
      });
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-publish'));
      await user.click(screen.getByTestId('publish-only'));

      await waitFor(() => {
        expect(screen.getByTestId('slug-setup-modal')).toBeInTheDocument();
      });
    });

    it('should cancel publish when cancel clicked', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-publish'));
      await user.click(screen.getByTestId('publish-cancel'));

      expect(screen.queryByTestId('publish-confirm-modal')).not.toBeInTheDocument();
      expect(mockPublishCategory).not.toHaveBeenCalled();
    });
  });

  describe('unpublishing a category', () => {
    it('should fetch preview and show unpublish confirm modal', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-unpublish'));

      await waitFor(() => {
        expect(mockGetUnpublishCategoryPreview).toHaveBeenCalledWith(3);
      });
      await waitFor(() => {
        expect(screen.getByTestId('unpublish-confirm-modal')).toBeInTheDocument();
      });
    });

    it('should call unpublishCategory on confirm', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-unpublish'));

      await waitFor(() => {
        expect(screen.getByTestId('unpublish-confirm-modal')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('unpublish-confirm'));

      await waitFor(() => {
        expect(mockUnpublishCategory).toHaveBeenCalledWith(3);
      });
    });

    it('should cancel unpublish when cancel clicked', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-unpublish'));

      await waitFor(() => {
        expect(screen.getByTestId('unpublish-confirm-modal')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('unpublish-cancel'));

      expect(screen.queryByTestId('unpublish-confirm-modal')).not.toBeInTheDocument();
      expect(mockUnpublishCategory).not.toHaveBeenCalled();
    });
  });

  describe('closing the modal', () => {
    it('should call onClose when close button clicked', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();
      render(<CategoryManagerModal {...defaultProps} onClose={onClose} />);

      await user.click(screen.getByLabelText('Close'));

      expect(onClose).toHaveBeenCalled();
    });

    it('should call onClose when native dialog close event fires', () => {
      const onClose = vi.fn();
      render(<CategoryManagerModal {...defaultProps} onClose={onClose} />);

      const dialog = document.querySelector('dialog');
      dialog!.dispatchEvent(new Event('close'));

      expect(onClose).toHaveBeenCalled();
    });

    it('should call onClose when backdrop is clicked', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();
      render(<CategoryManagerModal {...defaultProps} onClose={onClose} />);

      const dialog = document.querySelector('dialog');
      await user.click(dialog!);

      expect(onClose).toHaveBeenCalled();
    });

    it('should clear selection when footer Cancel is clicked with no unsaved changes', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();
      render(<CategoryManagerModal {...defaultProps} onClose={onClose} />);

      // Select a category to make the footer visible
      await user.click(screen.getByTestId('tree-select-1'));

      // Click Cancel in the modal footer
      const cancelButton = screen.getByRole('button', { name: 'Cancel' });
      await user.click(cancelButton);

      // Cancel should clear selection, not close modal
      expect(lastFormProps.isNew).toBe(false);
      expect(lastFormProps.category).toBeNull();
    });
  });

  describe('form props', () => {
    it('should pass categories, collectionId, and isNew to form', () => {
      render(<CategoryManagerModal {...defaultProps} />);

      expect(lastFormProps.categories).toEqual(mockCategories);
      expect(lastFormProps.collectionId).toBe(1);
      expect(lastFormProps.isNew).toBe(false);
      expect(lastFormProps.category).toBeNull();
    });

    it('should pass empty state form when no category selected', () => {
      render(<CategoryManagerModal {...defaultProps} />);

      expect(lastFormProps.category).toBeNull();
      expect(lastFormProps.isNew).toBe(false);
    });
  });

  describe('tree props', () => {
    it('should pass categories and selectedCategoryId to tree', () => {
      render(<CategoryManagerModal {...defaultProps} />);

      expect(lastTreeProps.categories).toEqual(mockCategories);
      expect(lastTreeProps.selectedCategoryId).toBeNull();
    });
  });

  describe('slug setup flow', () => {
    it('should close slug setup modal on cancel', async () => {
      const user = userEvent.setup();
      mockPublishCategory.mockResolvedValue({
        published: { type: 'category', id: 1, name: 'Bravo' },
        promoted: [],
        childrenPublished: 0,
        requiresSlugSetup: true,
      });
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-publish'));
      await user.click(screen.getByTestId('publish-only'));

      await waitFor(() => {
        expect(screen.getByTestId('slug-setup-modal')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('slug-cancel'));

      expect(screen.queryByTestId('slug-setup-modal')).not.toBeInTheDocument();
    });

    it('should close slug setup modal on confirm and reload categories', async () => {
      const user = userEvent.setup();
      mockPublishCategory.mockResolvedValue({
        published: { type: 'category', id: 1, name: 'Bravo' },
        promoted: [],
        childrenPublished: 0,
        requiresSlugSetup: true,
      });
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-publish'));
      await user.click(screen.getByTestId('publish-only'));

      await waitFor(() => {
        expect(screen.getByTestId('slug-setup-modal')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('slug-confirm'));

      await waitFor(() => {
        expect(screen.queryByTestId('slug-setup-modal')).not.toBeInTheDocument();
      });
    });
  });

  describe('successful publish with toast', () => {
    it('should show toast after successful publish without slug setup', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-publish'));
      await user.click(screen.getByTestId('publish-with-children'));

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith('Published!', undefined);
      });
    });

    it('should show toast after successful unpublish', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-unpublish'));

      await waitFor(() => {
        expect(screen.getByTestId('unpublish-confirm-modal')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('unpublish-confirm'));

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith('Unpublished!');
      });
    });
  });

  describe('error handling', () => {
    it('should handle publishCategory failure gracefully', async () => {
      const user = userEvent.setup();
      mockPublishCategory.mockRejectedValue(new Error('Publish failed'));
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-publish'));
      await user.click(screen.getByTestId('publish-with-children'));

      await waitFor(() => {
        expect(consoleSpy).toHaveBeenCalledWith('Failed to publish category:', expect.any(Error));
      });
      // Publish confirm should be dismissed
      expect(screen.queryByTestId('publish-confirm-modal')).not.toBeInTheDocument();

      consoleSpy.mockRestore();
    });

    it('should handle getUnpublishCategoryPreview failure gracefully', async () => {
      const user = userEvent.setup();
      mockGetUnpublishCategoryPreview.mockRejectedValue(new Error('Preview failed'));
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-unpublish'));

      await waitFor(() => {
        expect(consoleSpy).toHaveBeenCalledWith('Failed to get unpublish preview:', expect.any(Error));
      });

      consoleSpy.mockRestore();
    });

    it('should handle unpublishCategory failure gracefully', async () => {
      const user = userEvent.setup();
      mockUnpublishCategory.mockRejectedValue(new Error('Unpublish failed'));
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-unpublish'));

      await waitFor(() => {
        expect(screen.getByTestId('unpublish-confirm-modal')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('unpublish-confirm'));

      await waitFor(() => {
        expect(consoleSpy).toHaveBeenCalledWith('Failed to unpublish category:', expect.any(Error));
      });

      consoleSpy.mockRestore();
    });

    it('should handle updateCategory failure gracefully', async () => {
      const user = userEvent.setup();
      mockUpdateCategory.mockRejectedValue(new Error('Network error'));
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      await user.click(screen.getByTestId('form-save'));

      await waitFor(() => {
        expect(consoleSpy).toHaveBeenCalled();
      });

      consoleSpy.mockRestore();
    });

    it('should handle deleteCategory failure gracefully', async () => {
      const user = userEvent.setup();
      mockDeleteCategory.mockRejectedValue(new Error('Delete failed'));
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-select-1'));
      // Click Delete in footer
      const deleteButton = screen.getByRole('button', { name: 'Delete' });
      await user.click(deleteButton);
      // Confirm in the delete confirmation modal
      const confirmButtons = screen.getAllByRole('button', { name: 'Delete' });
      await user.click(confirmButtons[confirmButtons.length - 1]);

      await waitFor(() => {
        expect(consoleSpy).toHaveBeenCalled();
      });

      consoleSpy.mockRestore();
    });

    it('should handle reorderCategories failure gracefully', async () => {
      const user = userEvent.setup();
      mockReorderCategories.mockRejectedValue(new Error('Reorder failed'));
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-reorder'));

      await waitFor(() => {
        expect(consoleSpy).toHaveBeenCalled();
      });

      consoleSpy.mockRestore();
    });

    it('should handle reparent failure gracefully', async () => {
      const user = userEvent.setup();
      mockUpdateCategory.mockRejectedValue(new Error('Reparent failed'));
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-reparent'));

      await waitFor(() => {
        expect(consoleSpy).toHaveBeenCalled();
      });

      consoleSpy.mockRestore();
    });
  });
});
