import React from 'react';
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
  mockRequestPublish,
  mockRequestUnpublish,
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
      visibility: 'Private' as Category['visibility'],
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
      visibility: 'Private' as Category['visibility'],
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
      visibility: 'Public' as Category['visibility'],
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
      visibility: 'Private' as Category['visibility'],
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
    mockRequestPublish: vi.fn(),
    mockRequestUnpublish: vi.fn(),
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
  }),
}));

// Mock usePublish
vi.mock('../src/contexts/usePublish', () => ({
  usePublish: () => ({
    requestPublish: mockRequestPublish,
    requestUnpublish: mockRequestUnpublish,
    pendingIntent: null,
    clearIntent: vi.fn(),
  }),
}));

// Track props passed to child components
let lastTreeProps: Record<string, unknown> = {};
let lastFormProps: Record<string, unknown> = {};
// eslint-disable-next-line @typescript-eslint/no-unused-vars
let lastPopoverProps: Record<string, unknown> = {};

// Mock CategoryManagerTree
vi.mock('../src/components/category/CategoryManagerTree', () => ({
  default: (props: Record<string, unknown>) => {
    lastTreeProps = props;
    return (
      <div data-testid="category-manager-tree">
        <button data-testid="tree-edit-1" onClick={() => (props.onEditCategory as (id: number) => void)(1)}>Edit 1</button>
        <button data-testid="tree-edit-2" onClick={() => (props.onEditCategory as (id: number) => void)(2)}>Edit 2</button>
        <button data-testid="tree-add" onClick={props.onAdd as () => void}>Add</button>
        <button data-testid="tree-reorder" onClick={() => (props.onReorder as (u: { categoryId: number; sortOrder: number }[]) => void)([{ categoryId: 1, sortOrder: 0 }, { categoryId: 2, sortOrder: 1 }])}>Reorder</button>
        <button data-testid="tree-reparent" onClick={() => (props.onReparent as (id: number, parentId: number | null) => void)(3, 2)}>Reparent</button>
        {props.toolbarSlot as React.ReactNode}
      </div>
    );
  },
}));

// Mock CategoryManagerForm
vi.mock('../src/components/category/CategoryManagerForm', () => ({
  default: (props: Record<string, unknown>) => {
    lastFormProps = props;
    const formRef = props.formRef as React.RefObject<{ submit: () => void } | null> | undefined;
    if (formRef && 'current' in formRef) {
      (formRef as React.MutableRefObject<{ submit: () => void } | null>).current = {
        submit: () => (props.onSave as (u: { name: string; description: string; parentCategoryId: number | null; itemTemplateIds: number[] }) => void)({ name: 'Updated', description: 'Desc', parentCategoryId: null, itemTemplateIds: [] }),
      };
    }
    return (
      <div data-testid="category-manager-form">
        <button data-testid="form-save" onClick={() => (props.onSave as (u: { name: string; description: string; parentCategoryId: number | null; itemTemplateIds: number[] }) => void)({ name: 'Updated', description: 'Desc', parentCategoryId: null, itemTemplateIds: [] })}>Save</button>
        <button data-testid="form-back" onClick={props.onBack as () => void}>Back</button>
        <button data-testid="form-publish" onClick={() => (props.onPublish as (c: Category) => void)(mockCategories[0])}>Publish</button>
        <button data-testid="form-unpublish" onClick={() => (props.onUnpublish as (c: Category) => void)(mockCategories[2])}>Unpublish</button>
      </div>
    );
  },
}));

// Mock QuickCreatePopover
vi.mock('../src/components/category/QuickCreatePopover', () => ({
  default: (props: Record<string, unknown>) => {
    lastPopoverProps = props;
    if (!props.isVisible) return null;
    return (
      <div data-testid="quick-create-popover">
        <button data-testid="popover-save" onClick={() => (props.onSave as (name: string) => void)('Quick Cat')}>Popover Save</button>
        <button data-testid="popover-more" onClick={() => (props.onMoreDetails as (name: string) => void)('Quick Cat')}>Popover More</button>
        <button data-testid="popover-cancel" onClick={props.onCancel as () => void}>Popover Cancel</button>
      </div>
    );
  },
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
    lastPopoverProps = {};
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
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('rendering', () => {
    it('should not render dialog content when isOpen is false', () => {
      render(<CategoryManagerModal {...defaultProps} isOpen={false} />);

      expect(HTMLDialogElement.prototype.close).not.toHaveBeenCalled();
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

  describe('view state', () => {
    it('should open to tree view by default', () => {
      render(<CategoryManagerModal {...defaultProps} />);

      const track = document.querySelector('.categoryManager__track');
      expect(track).not.toBeNull();
      expect(track!.classList.contains('categoryManager__track--form')).toBe(false);
    });

    it('should slide to form when category row clicked', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-edit-1'));

      const track = document.querySelector('.categoryManager__track');
      expect(track!.classList.contains('categoryManager__track--form')).toBe(true);
      expect((lastFormProps.category as Category)?.categoryId).toBe(1);
      expect(lastFormProps.isNew).toBe(false);
    });

    it('should not auto-select on open', () => {
      render(<CategoryManagerModal {...defaultProps} />);

      // No category should be selected by default
      expect(lastFormProps.category).toBeNull();
    });

    it('should reset to tree view when modal re-opens', async () => {
      const user = userEvent.setup();
      const { rerender } = render(<CategoryManagerModal {...defaultProps} />);

      // Slide to form
      await user.click(screen.getByTestId('tree-edit-1'));
      const track = document.querySelector('.categoryManager__track');
      expect(track!.classList.contains('categoryManager__track--form')).toBe(true);

      // Close and re-open
      rerender(<CategoryManagerModal {...defaultProps} isOpen={false} />);
      rerender(<CategoryManagerModal {...defaultProps} isOpen={true} />);

      const trackAfter = document.querySelector('.categoryManager__track');
      expect(trackAfter!.classList.contains('categoryManager__track--form')).toBe(false);
    });
  });

  describe('quick create', () => {
    it('should show popover when add clicked', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-add'));

      expect(screen.getByTestId('quick-create-popover')).toBeInTheDocument();
    });

    it('should create category and stay on tree when popover Save clicked', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-add'));
      await user.click(screen.getByTestId('popover-save'));

      await waitFor(() => {
        expect(mockAddCategory).toHaveBeenCalledWith({
          collectionId: 1,
          name: 'Quick Cat',
          description: '',
          parentCategoryId: null,
          itemTemplateIds: [],
        });
      });

      // Should stay on tree view
      const track = document.querySelector('.categoryManager__track');
      expect(track!.classList.contains('categoryManager__track--form')).toBe(false);
    });

    it('should slide to form with name when More Details clicked', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-add'));
      await user.click(screen.getByTestId('popover-more'));

      const track = document.querySelector('.categoryManager__track');
      expect(track!.classList.contains('categoryManager__track--form')).toBe(true);
      expect(lastFormProps.isNew).toBe(true);
      expect(lastFormProps.initialName).toBe('Quick Cat');
    });

    it('should close popover on cancel', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-add'));
      expect(screen.getByTestId('quick-create-popover')).toBeInTheDocument();

      await user.click(screen.getByTestId('popover-cancel'));
      expect(screen.queryByTestId('quick-create-popover')).not.toBeInTheDocument();
    });
  });

  describe('saving a category (update)', () => {
    it('should call updateCategory and slide back to tree when saving existing category', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      // Edit a category first
      await user.click(screen.getByTestId('tree-edit-1'));
      // Save it
      await user.click(screen.getByTestId('form-save'));

      await waitFor(() => {
        expect(mockUpdateCategory).toHaveBeenCalledWith(1, { name: 'Updated', description: 'Desc', parentCategoryId: null, itemTemplateIds: [] });
      });
      await waitFor(() => {
        expect(mockLoadCategoriesForCollection).toHaveBeenCalledWith(1);
      });

      // Should slide back to tree
      const track = document.querySelector('.categoryManager__track');
      expect(track!.classList.contains('categoryManager__track--form')).toBe(false);
    });

    it('should call addCategory when saving in create mode', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      // Use quick-create More Details to enter create mode
      await user.click(screen.getByTestId('tree-add'));
      await user.click(screen.getByTestId('popover-more'));
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

  describe('deleting a category', () => {
    it('should call deleteCategory and slide back to tree', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      // Edit a category first
      await user.click(screen.getByTestId('tree-edit-1'));
      // Click the Delete button from form
      await user.click(screen.getByRole('button', { name: 'Delete' }));

      // Confirm in the delete confirmation modal
      const confirmButtons = screen.getAllByRole('button', { name: 'Delete' });
      // The confirmation modal's Delete button (last one)
      await user.click(confirmButtons[confirmButtons.length - 1]);

      await waitFor(() => {
        expect(mockDeleteCategory).toHaveBeenCalledWith(1);
      });

      // Should slide back to tree
      await waitFor(() => {
        const track = document.querySelector('.categoryManager__track');
        expect(track!.classList.contains('categoryManager__track--form')).toBe(false);
      });
    });

    it('should not call deleteCategory when confirm is cancelled', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-edit-1'));
      // Click the Delete button from form
      await user.click(screen.getByRole('button', { name: 'Delete' }));

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
        visibility: 'Private' as Category['visibility'],
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
    it('should call requestPublish with correct entity ref', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-edit-1'));
      await user.click(screen.getByTestId('form-publish'));

      expect(mockRequestPublish).toHaveBeenCalledWith([{ type: 'category', id: 1 }]);
    });
  });

  describe('unpublishing a category', () => {
    it('should call requestUnpublish with correct entity ref', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-edit-1'));
      await user.click(screen.getByTestId('form-unpublish'));

      expect(mockRequestUnpublish).toHaveBeenCalledWith([{ type: 'category', id: 3 }]);
    });
  });

  describe('closing the modal', () => {
    it('should call onClose when close button clicked from tree view', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();
      render(<CategoryManagerModal {...defaultProps} onClose={onClose} />);

      await user.click(screen.getByLabelText('Close'));

      expect(onClose).toHaveBeenCalled();
    });

    it('should slide back to tree when close clicked from form without changes', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();
      render(<CategoryManagerModal {...defaultProps} onClose={onClose} />);

      // Slide to form
      await user.click(screen.getByTestId('tree-edit-1'));
      const track = document.querySelector('.categoryManager__track');
      expect(track!.classList.contains('categoryManager__track--form')).toBe(true);

      // Close from form view
      await user.click(screen.getByLabelText('Close'));

      // Should slide back to tree, NOT close modal
      expect(onClose).not.toHaveBeenCalled();
      expect(track!.classList.contains('categoryManager__track--form')).toBe(false);
    });

    it('should call onClose when native dialog close event fires', () => {
      const onClose = vi.fn();
      render(<CategoryManagerModal {...defaultProps} onClose={onClose} />);

      const dialog = document.querySelector('dialog');
      dialog!.dispatchEvent(new Event('close'));

      expect(onClose).toHaveBeenCalled();
    });

    it('should call onClose when backdrop is clicked from tree view', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();
      render(<CategoryManagerModal {...defaultProps} onClose={onClose} />);

      const dialog = document.querySelector('dialog');
      await user.click(dialog!);

      expect(onClose).toHaveBeenCalled();
    });
  });

  describe('form props', () => {
    it('should pass categories, collectionId, and isNew to form', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      // Click to edit first
      await user.click(screen.getByTestId('tree-edit-1'));

      expect(lastFormProps.categories).toEqual(mockCategories);
      expect(lastFormProps.collectionId).toBe(1);
      expect(lastFormProps.isNew).toBe(false);
      expect((lastFormProps.category as Category)?.categoryId).toBe(1);
    });
  });

  describe('tree props', () => {
    it('should pass categories to tree', () => {
      render(<CategoryManagerModal {...defaultProps} />);

      expect(lastTreeProps.categories).toEqual(mockCategories);
    });
  });

  describe('error handling', () => {
    it('should handle updateCategory failure gracefully', async () => {
      const user = userEvent.setup();
      mockUpdateCategory.mockRejectedValue(new Error('Network error'));
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-edit-1'));
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

      await user.click(screen.getByTestId('tree-edit-1'));
      // Click Delete from form
      await user.click(screen.getByRole('button', { name: 'Delete' }));
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

    it('should handle quick create failure gracefully', async () => {
      const user = userEvent.setup();
      mockAddCategory.mockRejectedValue(new Error('Create failed'));
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-add'));
      await user.click(screen.getByTestId('popover-save'));

      await waitFor(() => {
        expect(consoleSpy).toHaveBeenCalledWith('Failed to create category:', expect.any(Error));
      });

      consoleSpy.mockRestore();
    });
  });
});
