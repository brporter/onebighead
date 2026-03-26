import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CategoryManagerForm from '../src/components/category/CategoryManagerForm';
import type { Category } from '../src/utils/types';
import { Visibility } from '../src/utils/types';

// Mock useData
vi.mock('../src/contexts/useData', () => ({
  useData: () => ({
    loadCollectionTemplates: vi.fn(async () => []),
    loadItemTemplates: vi.fn(async () => []),
    itemTemplates: [],
  }),
}));

// Mock CategoryTemplateSelector
vi.mock('../src/components/category/CategoryTemplateSelector', () => ({
  default: ({ selectedTemplateIds, onChange, disabled }: { selectedTemplateIds: number[]; onChange: (ids: number[]) => void; disabled?: boolean }) => (
    <div data-testid="category-template-selector">
      Template Selector (selected: {selectedTemplateIds.length})
      <button onClick={() => onChange([1, 2])} disabled={disabled}>Select Templates</button>
    </div>
  ),
}));

const makeCategory = (overrides: Partial<Category> = {}): Category => ({
  workspaceId: 1,
  collectionId: 1,
  categoryId: 1,
  name: 'Category 1',
  description: 'Description 1',
  parentCategoryId: null,
  isSystem: false,
  visibility: Visibility.Private,
  effectiveIsPublic: false,
  itemTemplateIds: [],
  sortOrder: 0,
  ...overrides,
});

const mockCategories: Category[] = [
  makeCategory({ categoryId: 1, name: 'Category 1' }),
  makeCategory({ categoryId: 2, name: 'Category 2' }),
  makeCategory({ categoryId: 3, name: 'Child of Category 1', parentCategoryId: 1 }),
  makeCategory({ categoryId: 99, name: 'Unassigned Items', isSystem: true }),
];

describe('CategoryManagerForm', () => {
  const defaultProps = {
    category: null as Category | null,
    categories: mockCategories,
    collectionId: 1,
    isNew: false,
    onSave: vi.fn(),
    onDelete: vi.fn(),
    onPublish: vi.fn(),
    onUnpublish: vi.fn(),
    onCancel: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('empty state', () => {
    it('should render empty state when no category is selected and not isNew', () => {
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={false} />);

      expect(screen.getByText('Select a category to edit, or click + to add a new one.')).toBeInTheDocument();
    });

    it('should not render form fields in empty state', () => {
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={false} />);

      expect(screen.queryByLabelText(/Name/)).not.toBeInTheDocument();
    });
  });

  describe('create mode', () => {
    it('should show empty form fields when isNew is true', () => {
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} />);

      expect(screen.getByLabelText(/Name/)).toHaveValue('');
      expect(screen.getByLabelText(/Description/)).toHaveValue('');
    });

    it('should show "Create" button text when isNew is true', () => {
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} />);

      expect(screen.getByRole('button', { name: 'Create' })).toBeInTheDocument();
    });

    it('should not show Delete button when isNew is true', () => {
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} />);

      expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
    });

    it('should show parent category dropdown without system categories', () => {
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} />);

      const options = screen.getAllByRole('option');
      const optionTexts = options.map((opt) => opt.textContent);
      expect(optionTexts).toContain('None (root level)');
      expect(optionTexts).toContain('Category 1');
      expect(optionTexts).toContain('Category 2');
      expect(optionTexts).not.toContain('Unassigned Items');
    });

    it('should show CategoryTemplateSelector', () => {
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} />);

      expect(screen.getByTestId('category-template-selector')).toBeInTheDocument();
    });
  });

  describe('edit mode', () => {
    const existingCategory = makeCategory({ categoryId: 1, name: 'Category 1', description: 'Description 1' });

    it('should render form fields when category is selected', () => {
      render(<CategoryManagerForm {...defaultProps} category={existingCategory} />);

      expect(screen.getByLabelText(/Name/)).toHaveValue('Category 1');
      expect(screen.getByLabelText(/Description/)).toHaveValue('Description 1');
    });

    it('should show header with category name', () => {
      render(<CategoryManagerForm {...defaultProps} category={existingCategory} />);

      expect(screen.getByText('Category 1')).toBeInTheDocument();
    });

    it('should show "Save Changes" button text when editing', () => {
      render(<CategoryManagerForm {...defaultProps} category={existingCategory} />);

      expect(screen.getByRole('button', { name: 'Save Changes' })).toBeInTheDocument();
    });

    it('should show Delete button when editing', () => {
      render(<CategoryManagerForm {...defaultProps} category={existingCategory} />);

      expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
    });

    it('should exclude self and descendants from parent dropdown', () => {
      render(<CategoryManagerForm {...defaultProps} category={existingCategory} />);

      const options = screen.getAllByRole('option');
      const optionTexts = options.map((opt) => opt.textContent);
      expect(optionTexts).not.toContain('Category 1');
      expect(optionTexts).not.toContain('Child of Category 1');
      expect(optionTexts).toContain('Category 2');
      expect(optionTexts).toContain('None (root level)');
    });

    it('should populate parent category dropdown with current value', () => {
      const childCategory = makeCategory({ categoryId: 3, name: 'Child of Category 1', parentCategoryId: 1 });
      render(<CategoryManagerForm {...defaultProps} category={childCategory} />);

      const parentSelect = screen.getByLabelText(/Parent Category/) as HTMLSelectElement;
      expect(parentSelect.value).toBe('1');
    });
  });

  describe('validation', () => {
    it('should disable Save button when name is empty', () => {
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} />);

      expect(screen.getByRole('button', { name: 'Create' })).toBeDisabled();
    });

    it('should enable Save button when name is provided', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} />);

      await user.type(screen.getByLabelText(/Name/), 'New Category');

      expect(screen.getByRole('button', { name: 'Create' })).toBeEnabled();
    });

    it('should show error for reserved name "Unassigned Items"', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} />);

      await user.type(screen.getByLabelText(/Name/), 'Unassigned Items');
      await user.click(screen.getByRole('button', { name: 'Create' }));

      expect(screen.getByRole('alert')).toHaveTextContent('"Unassigned Items" is a reserved name and cannot be used');
      expect(defaultProps.onSave).not.toHaveBeenCalled();
    });

    it('should validate reserved name case-insensitively', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} />);

      await user.type(screen.getByLabelText(/Name/), 'UNASSIGNED ITEMS');
      await user.click(screen.getByRole('button', { name: 'Create' }));

      expect(screen.getByRole('alert')).toHaveTextContent('reserved name');
      expect(defaultProps.onSave).not.toHaveBeenCalled();
    });
  });

  describe('save', () => {
    it('should call onSave with updated fields when Save is clicked', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      const existingCategory = makeCategory({ categoryId: 1, name: 'Category 1', description: 'Description 1' });

      render(<CategoryManagerForm {...defaultProps} category={existingCategory} onSave={onSave} />);

      await user.clear(screen.getByLabelText(/Name/));
      await user.type(screen.getByLabelText(/Name/), 'Updated Name');
      await user.click(screen.getByRole('button', { name: 'Save Changes' }));

      expect(onSave).toHaveBeenCalledWith({
        name: 'Updated Name',
        description: 'Description 1',
        parentCategoryId: null,
        itemTemplateIds: [],
      });
    });

    it('should call onSave with selected parent category', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();

      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} onSave={onSave} />);

      await user.type(screen.getByLabelText(/Name/), 'New Category');
      await user.selectOptions(screen.getByLabelText(/Parent Category/), '2');
      await user.click(screen.getByRole('button', { name: 'Create' }));

      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({ parentCategoryId: 2 })
      );
    });

    it('should call onSave with selected template ids', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();

      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} onSave={onSave} />);

      await user.type(screen.getByLabelText(/Name/), 'New Category');
      await user.click(screen.getByText('Select Templates'));
      await user.click(screen.getByRole('button', { name: 'Create' }));

      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({ itemTemplateIds: [1, 2] })
      );
    });

    it('should trim name and description before saving', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();

      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} onSave={onSave} />);

      await user.type(screen.getByLabelText(/Name/), '  New Category  ');
      await user.type(screen.getByLabelText(/Description/), '  Some description  ');
      await user.click(screen.getByRole('button', { name: 'Create' }));

      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'New Category',
          description: 'Some description',
        })
      );
    });
  });

  describe('delete', () => {
    it('should call onDelete when Delete is clicked', async () => {
      const user = userEvent.setup();
      const onDelete = vi.fn();
      const existingCategory = makeCategory({ categoryId: 5, name: 'To Delete' });

      render(<CategoryManagerForm {...defaultProps} category={existingCategory} onDelete={onDelete} />);

      await user.click(screen.getByRole('button', { name: 'Delete' }));

      expect(onDelete).toHaveBeenCalledWith(5);
    });
  });

  describe('cancel', () => {
    it('should call onCancel when Cancel button is clicked', async () => {
      const user = userEvent.setup();
      const onCancel = vi.fn();
      const existingCategory = makeCategory();

      render(<CategoryManagerForm {...defaultProps} category={existingCategory} onCancel={onCancel} />);

      await user.click(screen.getByRole('button', { name: 'Cancel' }));

      expect(onCancel).toHaveBeenCalled();
    });

    it('should call onCancel in create mode', async () => {
      const user = userEvent.setup();
      const onCancel = vi.fn();

      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} onCancel={onCancel} />);

      await user.click(screen.getByRole('button', { name: 'Cancel' }));

      expect(onCancel).toHaveBeenCalled();
    });
  });

  describe('system categories', () => {
    const systemCategory = makeCategory({
      categoryId: 99,
      name: 'Unassigned Items',
      description: 'System category',
      isSystem: true,
    });

    it('should show "System categories cannot be modified." message', () => {
      render(<CategoryManagerForm {...defaultProps} category={systemCategory} />);

      expect(screen.getByText('System categories cannot be modified.')).toBeInTheDocument();
    });

    it('should show disabled form fields for system categories', () => {
      render(<CategoryManagerForm {...defaultProps} category={systemCategory} />);

      expect(screen.getByDisplayValue('Unassigned Items')).toBeDisabled();
      expect(screen.getByDisplayValue('System category')).toBeDisabled();
    });

    it('should not show Save or Delete buttons for system categories', () => {
      render(<CategoryManagerForm {...defaultProps} category={systemCategory} />);

      expect(screen.queryByRole('button', { name: 'Save Changes' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
    });
  });

  describe('publish / unpublish', () => {
    it('should show "Publish" button when category is private', () => {
      const privateCategory = makeCategory({ visibility: Visibility.Private, effectiveIsPublic: false });
      render(<CategoryManagerForm {...defaultProps} category={privateCategory} />);

      expect(screen.getByRole('button', { name: 'Publish' })).toBeInTheDocument();
    });

    it('should show "Unpublish" button when category is public', () => {
      const publicCategory = makeCategory({ visibility: Visibility.Public, effectiveIsPublic: true });
      render(<CategoryManagerForm {...defaultProps} category={publicCategory} />);

      expect(screen.getByRole('button', { name: 'Unpublish' })).toBeInTheDocument();
    });

    it('should call onPublish when Publish button is clicked', async () => {
      const user = userEvent.setup();
      const onPublish = vi.fn();
      const privateCategory = makeCategory({ visibility: Visibility.Private, effectiveIsPublic: false });

      render(<CategoryManagerForm {...defaultProps} category={privateCategory} onPublish={onPublish} />);

      await user.click(screen.getByRole('button', { name: 'Publish' }));

      expect(onPublish).toHaveBeenCalledWith(privateCategory);
    });

    it('should call onUnpublish when Unpublish button is clicked', async () => {
      const user = userEvent.setup();
      const onUnpublish = vi.fn();
      const publicCategory = makeCategory({ visibility: Visibility.Public, effectiveIsPublic: true });

      render(<CategoryManagerForm {...defaultProps} category={publicCategory} onUnpublish={onUnpublish} />);

      await user.click(screen.getByRole('button', { name: 'Unpublish' }));

      expect(onUnpublish).toHaveBeenCalledWith(publicCategory);
    });

    it('should show public status text when category is public', () => {
      const publicCategory = makeCategory({ visibility: Visibility.Public, effectiveIsPublic: true });
      render(<CategoryManagerForm {...defaultProps} category={publicCategory} />);

      const publicTexts = screen.getAllByText('Public');
      expect(publicTexts.length).toBeGreaterThanOrEqual(1);
    });

    it('should show private status text when category is private', () => {
      const privateCategory = makeCategory({ visibility: Visibility.Private, effectiveIsPublic: false });
      render(<CategoryManagerForm {...defaultProps} category={privateCategory} />);

      const privateTexts = screen.getAllByText('Private');
      expect(privateTexts.length).toBeGreaterThanOrEqual(1);
    });

    it('should not show publish/unpublish for system categories', () => {
      const systemCategory = makeCategory({ categoryId: 99, isSystem: true });
      render(<CategoryManagerForm {...defaultProps} category={systemCategory} />);

      expect(screen.queryByRole('button', { name: 'Publish' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Unpublish' })).not.toBeInTheDocument();
    });

    it('should not show publish/unpublish in create mode', () => {
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} />);

      expect(screen.queryByRole('button', { name: 'Publish' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Unpublish' })).not.toBeInTheDocument();
    });
  });

  describe('form reset on category change', () => {
    it('should update form fields when category prop changes', () => {
      const category1 = makeCategory({ categoryId: 1, name: 'Category 1', description: 'Desc 1' });
      const category2 = makeCategory({ categoryId: 2, name: 'Category 2', description: 'Desc 2' });

      const { rerender } = render(<CategoryManagerForm {...defaultProps} category={category1} />);

      expect(screen.getByLabelText(/Name/)).toHaveValue('Category 1');

      rerender(<CategoryManagerForm {...defaultProps} category={category2} />);

      expect(screen.getByLabelText(/Name/)).toHaveValue('Category 2');
      expect(screen.getByLabelText(/Description/)).toHaveValue('Desc 2');
    });

    it('should reset form fields when switching to create mode', () => {
      const existingCategory = makeCategory({ categoryId: 1, name: 'Category 1' });

      const { rerender } = render(<CategoryManagerForm {...defaultProps} category={existingCategory} />);

      expect(screen.getByLabelText(/Name/)).toHaveValue('Category 1');

      rerender(<CategoryManagerForm {...defaultProps} category={null} isNew={true} />);

      expect(screen.getByLabelText(/Name/)).toHaveValue('');
    });
  });
});
