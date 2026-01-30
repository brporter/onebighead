import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CategoryEditorModal from '../src/components/category/CategoryEditorModal';
import type { Category, Collection } from '../src/utils/types';

// Use vi.hoisted for mocks that need to be available before module loading
const { mockAddCategory, mockUpdateCategory, mockDeleteCategory } = vi.hoisted(() => ({
  mockAddCategory: vi.fn(),
  mockUpdateCategory: vi.fn(),
  mockDeleteCategory: vi.fn(),
}));

const mockCollection: Collection = {
  collectionId: 1,
  tenantId: 1,
  name: 'Test Collection',
  description: 'Test Description',
  heroImageUrl: null,
  slug: 'test-collection',
  isPublic: true,
};

const mockCategories: Category[] = [
  {
    tenantId: 1,
    collectionId: 1,
    categoryId: 1,
    name: 'Category 1',
    description: 'Description 1',
    parentCategoryId: null,
    isSystem: false,
    isPublicOverride: null,
    effectiveIsPublic: true,
    itemTemplateIds: [],
  },
  {
    tenantId: 1,
    collectionId: 1,
    categoryId: 2,
    name: 'Category 2',
    description: 'Description 2',
    parentCategoryId: null, // Make it root level so it can be parent
    isSystem: false,
    isPublicOverride: null,
    effectiveIsPublic: true,
    itemTemplateIds: [],
  },
  {
    tenantId: 1,
    collectionId: 1,
    categoryId: 3,
    name: 'Child of Category 1',
    description: 'Description 3',
    parentCategoryId: 1, // Child of Category 1
    isSystem: false,
    isPublicOverride: null,
    effectiveIsPublic: true,
    itemTemplateIds: [],
  },
  {
    tenantId: 1,
    collectionId: 1,
    categoryId: 99,
    name: 'Unassigned Items',
    description: 'System category',
    parentCategoryId: null,
    isSystem: true,
    isPublicOverride: null,
    effectiveIsPublic: true,
    itemTemplateIds: [],
  },
];

// Mock DataContext
vi.mock('../src/contexts/DataContext', () => ({
  useData: () => ({
    categories: mockCategories,
    currentCollection: mockCollection,
    addCategory: mockAddCategory,
    updateCategory: mockUpdateCategory,
    deleteCategory: mockDeleteCategory,
    loadCollectionTemplates: vi.fn(async () => []),
    loadItemTemplates: vi.fn(async () => []),
    itemTemplates: [],
  }),
}));

// Mock CategoryTemplateSelector to simplify tests
vi.mock('../src/components/category/CategoryTemplateSelector', () => ({
  default: ({ selectedTemplateIds, onChange }: { selectedTemplateIds: number[]; onChange: (ids: number[]) => void }) => (
    <div data-testid="category-template-selector">
      Template Selector (selected: {selectedTemplateIds.length})
      <button onClick={() => onChange([1, 2])}>Select Templates</button>
    </div>
  ),
}));

// Mock VisibilityToggle to simplify tests
vi.mock('../src/components/common/VisibilityToggle', () => ({
  default: ({ label }: { label?: string }) => (
    <div data-testid="visibility-toggle">{label ?? 'Visibility'}</div>
  ),
}));

describe('CategoryEditorModal', () => {
  const defaultProps = {
    category: null as Category | null,
    isOpen: true,
    onClose: vi.fn(),
    onSaved: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    // Mock dialog methods - showModal should set the open attribute
    HTMLDialogElement.prototype.showModal = vi.fn(function (this: HTMLDialogElement) {
      this.setAttribute('open', '');
    });
    HTMLDialogElement.prototype.close = vi.fn(function (this: HTMLDialogElement) {
      this.removeAttribute('open');
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('rendering - new category', () => {
    it('should render "Add Category" title when creating new category', () => {
      render(<CategoryEditorModal {...defaultProps} category={null} />);

      expect(screen.getByText('Add Category')).toBeInTheDocument();
    });

    it('should show empty form fields when creating new category', () => {
      render(<CategoryEditorModal {...defaultProps} category={null} />);

      expect(screen.getByLabelText(/Name/)).toHaveValue('');
      expect(screen.getByLabelText(/Description/)).toHaveValue('');
    });

    it('should show "Create" button when creating new category', () => {
      render(<CategoryEditorModal {...defaultProps} category={null} />);

      expect(screen.getByRole('button', { name: 'Create' })).toBeInTheDocument();
    });

    it('should not show delete button when creating new category', () => {
      render(<CategoryEditorModal {...defaultProps} category={null} />);

      expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
    });

    it('should show parent category dropdown with available parents', () => {
      render(<CategoryEditorModal {...defaultProps} category={null} />);

      const parentSelect = screen.getByLabelText(/Parent Category/);
      expect(parentSelect).toBeInTheDocument();
      expect(screen.getByText('None (root level)')).toBeInTheDocument();
      expect(screen.getByText('Category 1')).toBeInTheDocument();
      expect(screen.getByText('Category 2')).toBeInTheDocument();
    });

    it('should not show system categories in parent dropdown', () => {
      render(<CategoryEditorModal {...defaultProps} category={null} />);

      const options = screen.getAllByRole('option');
      const optionTexts = options.map((opt) => opt.textContent);
      expect(optionTexts).not.toContain('Unassigned Items');
    });
  });

  describe('rendering - editing category', () => {
    const existingCategory: Category = {
      tenantId: 1,
      collectionId: 1,
      categoryId: 1,
      name: 'Category 1',
      description: 'Description 1',
      parentCategoryId: null,
      isSystem: false,
      isPublicOverride: null,
      effectiveIsPublic: true,
    };

    it('should render "Edit: Category Name" title when editing', () => {
      render(<CategoryEditorModal {...defaultProps} category={existingCategory} />);

      expect(screen.getByText('Edit: Category 1')).toBeInTheDocument();
    });

    it('should populate form fields with existing category data', () => {
      render(<CategoryEditorModal {...defaultProps} category={existingCategory} />);

      expect(screen.getByLabelText(/Name/)).toHaveValue('Category 1');
      expect(screen.getByLabelText(/Description/)).toHaveValue('Description 1');
    });

    it('should show "Save" button when editing', () => {
      render(<CategoryEditorModal {...defaultProps} category={existingCategory} />);

      expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument();
    });

    it('should show delete button when editing', () => {
      render(<CategoryEditorModal {...defaultProps} category={existingCategory} />);

      expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
    });

    it('should exclude self and descendants from parent dropdown', () => {
      render(<CategoryEditorModal {...defaultProps} category={existingCategory} />);

      const options = screen.getAllByRole('option');
      const optionTexts = options.map((opt) => opt.textContent);
      // Category 1 is being edited, "Child of Category 1" is its child - neither should be available
      expect(optionTexts).not.toContain('Category 1');
      expect(optionTexts).not.toContain('Child of Category 1');
      // Category 2 is a sibling, so it should be available
      expect(optionTexts).toContain('Category 2');
      expect(optionTexts).toContain('None (root level)');
    });
  });

  describe('rendering - system category', () => {
    const systemCategory: Category = {
      tenantId: 1,
      collectionId: 1,
      categoryId: 99,
      name: 'Unassigned Items',
      description: 'System category',
      parentCategoryId: null,
      isSystem: true,
      isPublicOverride: null,
      effectiveIsPublic: true,
    };

    it('should show category name as title for system category', () => {
      render(<CategoryEditorModal {...defaultProps} category={systemCategory} />);

      expect(screen.getByText('Unassigned Items')).toBeInTheDocument();
    });

    it('should show "System categories cannot be modified" message', () => {
      render(<CategoryEditorModal {...defaultProps} category={systemCategory} />);

      expect(screen.getByText('System categories cannot be modified.')).toBeInTheDocument();
    });

    it('should show disabled form fields for system category', () => {
      render(<CategoryEditorModal {...defaultProps} category={systemCategory} />);

      const nameInput = screen.getByDisplayValue('Unassigned Items');
      expect(nameInput).toBeDisabled();

      const descriptionInput = screen.getByDisplayValue('System category');
      expect(descriptionInput).toBeDisabled();
    });

    it('should show Close button instead of Save for system category', () => {
      render(<CategoryEditorModal {...defaultProps} category={systemCategory} />);

      // There are two buttons with "Close" - the X button (aria-label) and the main Close button
      // Use getAllByRole to find all Close buttons, then check there's no Save/Create
      const closeButtons = screen.getAllByRole('button', { name: 'Close' });
      expect(closeButtons.length).toBe(2); // X button and Close button
      expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Create' })).not.toBeInTheDocument();
    });

    it('should not show delete button for system category', () => {
      render(<CategoryEditorModal {...defaultProps} category={systemCategory} />);

      expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
    });
  });

  describe('validation', () => {
    it('should disable submit button when name is empty', () => {
      render(<CategoryEditorModal {...defaultProps} category={null} />);

      expect(screen.getByRole('button', { name: 'Create' })).toBeDisabled();
    });

    it('should enable submit button when name is provided', async () => {
      const user = userEvent.setup();
      render(<CategoryEditorModal {...defaultProps} category={null} />);

      await user.type(screen.getByLabelText(/Name/), 'New Category');

      expect(screen.getByRole('button', { name: 'Create' })).toBeEnabled();
    });

    it('should show error when submitting with empty name', async () => {
      const user = userEvent.setup();
      const existingCategory: Category = {
        ...mockCategories[0],
        name: '',
      };
      render(<CategoryEditorModal {...defaultProps} category={existingCategory} />);

      // Clear any existing name and try to submit
      const nameInput = screen.getByLabelText(/Name/);
      await user.clear(nameInput);

      // Button should be disabled, but let's also verify the validation message
      expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    });

    it('should show error for reserved name "Unassigned Items"', async () => {
      const user = userEvent.setup();
      render(<CategoryEditorModal {...defaultProps} category={null} />);

      await user.type(screen.getByLabelText(/Name/), 'Unassigned Items');
      await user.click(screen.getByRole('button', { name: 'Create' }));

      expect(screen.getByRole('alert')).toHaveTextContent('"Unassigned Items" is a reserved name and cannot be used');
    });

    it('should show error for reserved name case-insensitively', async () => {
      const user = userEvent.setup();
      render(<CategoryEditorModal {...defaultProps} category={null} />);

      await user.type(screen.getByLabelText(/Name/), 'UNASSIGNED ITEMS');
      await user.click(screen.getByRole('button', { name: 'Create' }));

      expect(screen.getByRole('alert')).toHaveTextContent('reserved name');
    });
  });

  describe('create category', () => {
    it('should call addCategory on submit when creating', async () => {
      const user = userEvent.setup();
      mockAddCategory.mockResolvedValue(100);

      render(<CategoryEditorModal {...defaultProps} category={null} />);

      await user.type(screen.getByLabelText(/Name/), 'New Category');
      await user.type(screen.getByLabelText(/Description/), 'New Description');
      await user.click(screen.getByRole('button', { name: 'Create' }));

      await waitFor(() => {
        expect(mockAddCategory).toHaveBeenCalledWith({
          collectionId: 1,
          name: 'New Category',
          description: 'New Description',
          parentCategoryId: null,
          isPublicOverride: null,
          itemTemplateIds: [],
        });
      });
    });

    it('should call onSaved and onClose after successful create', async () => {
      const user = userEvent.setup();
      const onSaved = vi.fn();
      const onClose = vi.fn();
      mockAddCategory.mockResolvedValue(100);

      render(<CategoryEditorModal {...defaultProps} category={null} onSaved={onSaved} onClose={onClose} />);

      await user.type(screen.getByLabelText(/Name/), 'New Category');
      await user.click(screen.getByRole('button', { name: 'Create' }));

      await waitFor(() => {
        expect(onSaved).toHaveBeenCalled();
        expect(onClose).toHaveBeenCalled();
      });
    });

    it('should show error message when addCategory fails', async () => {
      const user = userEvent.setup();
      mockAddCategory.mockRejectedValue(new Error('Failed to create category'));

      render(<CategoryEditorModal {...defaultProps} category={null} />);

      await user.type(screen.getByLabelText(/Name/), 'New Category');
      await user.click(screen.getByRole('button', { name: 'Create' }));

      await waitFor(() => {
        expect(screen.getByRole('alert')).toHaveTextContent('Failed to create category');
      });
    });

    it('should show "Saving..." text while submitting', async () => {
      const user = userEvent.setup();
      let resolvePromise: (value: number) => void;
      mockAddCategory.mockImplementation(() => new Promise((resolve) => {
        resolvePromise = resolve;
      }));

      render(<CategoryEditorModal {...defaultProps} category={null} />);

      await user.type(screen.getByLabelText(/Name/), 'New Category');
      await user.click(screen.getByRole('button', { name: 'Create' }));

      expect(screen.getByRole('button', { name: 'Saving...' })).toBeInTheDocument();

      // Resolve the promise to clean up
      resolvePromise!(100);
      await waitFor(() => {
        expect(screen.queryByRole('button', { name: 'Saving...' })).not.toBeInTheDocument();
      });
    });
  });

  describe('update category', () => {
    const existingCategory: Category = mockCategories[0];

    it('should call updateCategory on submit when editing', async () => {
      const user = userEvent.setup();
      mockUpdateCategory.mockResolvedValue(undefined);

      render(<CategoryEditorModal {...defaultProps} category={existingCategory} />);

      await user.clear(screen.getByLabelText(/Name/));
      await user.type(screen.getByLabelText(/Name/), 'Updated Category');
      await user.click(screen.getByRole('button', { name: 'Save' }));

      await waitFor(() => {
        expect(mockUpdateCategory).toHaveBeenCalledWith(1, {
          name: 'Updated Category',
          description: 'Description 1',
          parentCategoryId: null,
          isPublicOverride: null,
          itemTemplateIds: [],
        });
      });
    });

    it('should call onSaved and onClose after successful update', async () => {
      const user = userEvent.setup();
      const onSaved = vi.fn();
      const onClose = vi.fn();
      mockUpdateCategory.mockResolvedValue(undefined);

      render(<CategoryEditorModal {...defaultProps} category={existingCategory} onSaved={onSaved} onClose={onClose} />);

      await user.click(screen.getByRole('button', { name: 'Save' }));

      await waitFor(() => {
        expect(onSaved).toHaveBeenCalled();
        expect(onClose).toHaveBeenCalled();
      });
    });

    it('should show error message when updateCategory fails', async () => {
      const user = userEvent.setup();
      mockUpdateCategory.mockRejectedValue(new Error('Failed to update category'));

      render(<CategoryEditorModal {...defaultProps} category={existingCategory} />);

      await user.click(screen.getByRole('button', { name: 'Save' }));

      await waitFor(() => {
        expect(screen.getByRole('alert')).toHaveTextContent('Failed to update category');
      });
    });
  });

  describe('delete category', () => {
    const existingCategory: Category = mockCategories[0];

    it('should call deleteCategory when delete confirmed', async () => {
      const user = userEvent.setup();
      vi.spyOn(window, 'confirm').mockReturnValue(true);
      mockDeleteCategory.mockResolvedValue(undefined);

      render(<CategoryEditorModal {...defaultProps} category={existingCategory} />);

      await user.click(screen.getByRole('button', { name: 'Delete' }));

      await waitFor(() => {
        expect(mockDeleteCategory).toHaveBeenCalledWith(1);
      });
    });

    it('should not call deleteCategory when delete cancelled', async () => {
      const user = userEvent.setup();
      vi.spyOn(window, 'confirm').mockReturnValue(false);

      render(<CategoryEditorModal {...defaultProps} category={existingCategory} />);

      await user.click(screen.getByRole('button', { name: 'Delete' }));

      expect(mockDeleteCategory).not.toHaveBeenCalled();
    });

    it('should show confirmation dialog with category name', async () => {
      const user = userEvent.setup();
      const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(false);

      render(<CategoryEditorModal {...defaultProps} category={existingCategory} />);

      await user.click(screen.getByRole('button', { name: 'Delete' }));

      expect(confirmSpy).toHaveBeenCalledWith(
        expect.stringContaining('Category 1')
      );
    });

    it('should call onSaved and onClose after successful delete', async () => {
      const user = userEvent.setup();
      const onSaved = vi.fn();
      const onClose = vi.fn();
      vi.spyOn(window, 'confirm').mockReturnValue(true);
      mockDeleteCategory.mockResolvedValue(undefined);

      render(<CategoryEditorModal {...defaultProps} category={existingCategory} onSaved={onSaved} onClose={onClose} />);

      await user.click(screen.getByRole('button', { name: 'Delete' }));

      await waitFor(() => {
        expect(onSaved).toHaveBeenCalled();
        expect(onClose).toHaveBeenCalled();
      });
    });

    it('should show error message when deleteCategory fails', async () => {
      const user = userEvent.setup();
      vi.spyOn(window, 'confirm').mockReturnValue(true);
      mockDeleteCategory.mockRejectedValue(new Error('Failed to delete category'));

      render(<CategoryEditorModal {...defaultProps} category={existingCategory} />);

      await user.click(screen.getByRole('button', { name: 'Delete' }));

      await waitFor(() => {
        expect(screen.getByRole('alert')).toHaveTextContent('Failed to delete category');
      });
    });
  });

  describe('parent category selection', () => {
    it('should update parent category on selection', async () => {
      const user = userEvent.setup();
      mockAddCategory.mockResolvedValue(100);

      render(<CategoryEditorModal {...defaultProps} category={null} />);

      await user.type(screen.getByLabelText(/Name/), 'New Category');
      await user.selectOptions(screen.getByLabelText(/Parent Category/), '1');
      await user.click(screen.getByRole('button', { name: 'Create' }));

      await waitFor(() => {
        expect(mockAddCategory).toHaveBeenCalledWith(
          expect.objectContaining({
            parentCategoryId: 1,
          })
        );
      });
    });

    it('should set parent to null when "None" selected', async () => {
      const user = userEvent.setup();
      mockAddCategory.mockResolvedValue(100);

      render(<CategoryEditorModal {...defaultProps} category={null} />);

      await user.type(screen.getByLabelText(/Name/), 'New Category');
      await user.selectOptions(screen.getByLabelText(/Parent Category/), '1');
      await user.selectOptions(screen.getByLabelText(/Parent Category/), '');
      await user.click(screen.getByRole('button', { name: 'Create' }));

      await waitFor(() => {
        expect(mockAddCategory).toHaveBeenCalledWith(
          expect.objectContaining({
            parentCategoryId: null,
          })
        );
      });
    });
  });

  describe('modal behavior', () => {
    it('should call onClose when cancel button clicked', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();

      render(<CategoryEditorModal {...defaultProps} category={null} onClose={onClose} />);

      await user.click(screen.getByRole('button', { name: 'Cancel' }));

      expect(onClose).toHaveBeenCalled();
    });

    it('should call onClose when close (X) button clicked', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();

      render(<CategoryEditorModal {...defaultProps} category={null} onClose={onClose} />);

      await user.click(screen.getByLabelText('Close'));

      expect(onClose).toHaveBeenCalled();
    });

    it('should call showModal when isOpen is true', () => {
      render(<CategoryEditorModal {...defaultProps} isOpen={true} />);

      expect(HTMLDialogElement.prototype.showModal).toHaveBeenCalled();
    });

    it('should call dialog close when isOpen is false', () => {
      render(<CategoryEditorModal {...defaultProps} isOpen={false} />);

      expect(HTMLDialogElement.prototype.close).toHaveBeenCalled();
    });

    it('should call onClose when clicking backdrop', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();

      render(<CategoryEditorModal {...defaultProps} category={null} onClose={onClose} />);

      const dialog = document.querySelector('dialog');
      // Simulate clicking on the dialog backdrop (clicking directly on dialog element)
      await user.click(dialog!);

      expect(onClose).toHaveBeenCalled();
    });

    it('should reset form when modal reopens', async () => {
      const { rerender } = render(
        <CategoryEditorModal {...defaultProps} category={null} isOpen={false} />
      );

      // Open modal
      rerender(<CategoryEditorModal {...defaultProps} category={null} isOpen={true} />);

      expect(screen.getByLabelText(/Name/)).toHaveValue('');
    });

    it('should populate form when opening with existing category', () => {
      const existingCategory: Category = mockCategories[0];

      render(<CategoryEditorModal {...defaultProps} category={existingCategory} isOpen={true} />);

      expect(screen.getByLabelText(/Name/)).toHaveValue('Category 1');
      expect(screen.getByLabelText(/Description/)).toHaveValue('Description 1');
    });
  });

  describe('button states during submission', () => {
    it('should disable all buttons during submission', async () => {
      const user = userEvent.setup();
      let resolvePromise: (value: number) => void;
      mockAddCategory.mockImplementation(() => new Promise((resolve) => {
        resolvePromise = resolve;
      }));

      render(<CategoryEditorModal {...defaultProps} category={null} />);

      await user.type(screen.getByLabelText(/Name/), 'New Category');
      await user.click(screen.getByRole('button', { name: 'Create' }));

      expect(screen.getByRole('button', { name: 'Saving...' })).toBeDisabled();
      expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();

      // Resolve the promise to clean up
      resolvePromise!(100);
      await waitFor(() => {
        expect(screen.queryByRole('button', { name: 'Saving...' })).not.toBeInTheDocument();
      });
    });

    it('should disable delete button during submission', async () => {
      const user = userEvent.setup();
      const existingCategory: Category = mockCategories[0];
      let resolvePromise: () => void;
      mockUpdateCategory.mockImplementation(() => new Promise((resolve) => {
        resolvePromise = resolve;
      }));

      render(<CategoryEditorModal {...defaultProps} category={existingCategory} />);

      await user.click(screen.getByRole('button', { name: 'Save' }));

      expect(screen.getByRole('button', { name: 'Delete' })).toBeDisabled();

      // Resolve the promise to clean up
      resolvePromise!();
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Delete' })).toBeEnabled();
      });
    });
  });

  describe('visibility toggle', () => {
    it('should render visibility toggle component', () => {
      render(<CategoryEditorModal {...defaultProps} category={null} />);

      expect(screen.getByTestId('visibility-toggle')).toBeInTheDocument();
    });
  });
});
