import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
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
    onBack: vi.fn(),
    initialName: '',
    onPublish: vi.fn(),
    onUnpublish: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('empty state', () => {
    it('should render empty div when no category is selected and not isNew', () => {
      const { container } = render(<CategoryManagerForm {...defaultProps} category={null} isNew={false} />);

      const formDiv = container.querySelector('.category-manager-form');
      expect(formDiv).toBeInTheDocument();
      expect(formDiv!.children.length).toBe(0);
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
    it('should show error for reserved name "Unassigned Items" via formRef submit', async () => {
      const user = userEvent.setup();
      const formRef = { current: null as { submit: () => void } | null };
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} formRef={formRef} />);

      await user.type(screen.getByLabelText(/Name/), 'Unassigned Items');
      act(() => {
        formRef.current?.submit();
      });

      expect(screen.getByRole('alert')).toHaveTextContent('"Unassigned Items" is a reserved name and cannot be used');
      expect(defaultProps.onSave).not.toHaveBeenCalled();
    });

    it('should validate reserved name case-insensitively via formRef submit', async () => {
      const user = userEvent.setup();
      const formRef = { current: null as { submit: () => void } | null };
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} formRef={formRef} />);

      await user.type(screen.getByLabelText(/Name/), 'UNASSIGNED ITEMS');
      act(() => {
        formRef.current?.submit();
      });

      expect(screen.getByRole('alert')).toHaveTextContent('reserved name');
      expect(defaultProps.onSave).not.toHaveBeenCalled();
    });

    it('should show error for empty name via formRef submit', () => {
      const formRef = { current: null as { submit: () => void } | null };
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} formRef={formRef} />);

      act(() => {
        formRef.current?.submit();
      });

      expect(screen.getByRole('alert')).toHaveTextContent('Name is required');
      expect(defaultProps.onSave).not.toHaveBeenCalled();
    });
  });

  describe('save via formRef', () => {
    it('should call onSave with updated fields when formRef.submit() is called', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      const existingCategory = makeCategory({ categoryId: 1, name: 'Category 1', description: 'Description 1' });
      const formRef = { current: null as { submit: () => void } | null };

      render(<CategoryManagerForm {...defaultProps} category={existingCategory} onSave={onSave} formRef={formRef} />);

      await user.clear(screen.getByLabelText(/Name/));
      await user.type(screen.getByLabelText(/Name/), 'Updated Name');
      act(() => {
        formRef.current?.submit();
      });

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
      const formRef = { current: null as { submit: () => void } | null };

      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} onSave={onSave} formRef={formRef} />);

      await user.type(screen.getByLabelText(/Name/), 'New Category');
      await user.selectOptions(screen.getByLabelText(/Parent Category/), '2');
      act(() => {
        formRef.current?.submit();
      });

      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({ parentCategoryId: 2 })
      );
    });

    it('should call onSave with selected template ids', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      const formRef = { current: null as { submit: () => void } | null };

      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} onSave={onSave} formRef={formRef} />);

      await user.type(screen.getByLabelText(/Name/), 'New Category');
      await user.click(screen.getByText('Select Templates'));
      act(() => {
        formRef.current?.submit();
      });

      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({ itemTemplateIds: [1, 2] })
      );
    });

    it('should trim name and description before saving', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      const formRef = { current: null as { submit: () => void } | null };

      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} onSave={onSave} formRef={formRef} />);

      await user.type(screen.getByLabelText(/Name/), '  New Category  ');
      await user.type(screen.getByLabelText(/Description/), '  Some description  ');
      act(() => {
        formRef.current?.submit();
      });

      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'New Category',
          description: 'Some description',
        })
      );
    });
  });

  describe('onHasChanges callback', () => {
    it('calls onHasChanges when form fields change', async () => {
      const user = userEvent.setup();
      const onHasChanges = vi.fn();
      render(<CategoryManagerForm {...defaultProps} category={null} isNew={true} onHasChanges={onHasChanges} />);

      // Initially no changes
      expect(onHasChanges).toHaveBeenCalledWith(false);

      await user.type(screen.getByLabelText(/Name/), 'Something');

      expect(onHasChanges).toHaveBeenCalledWith(true);
    });

    it('calls onHasChanges(true) when editing an existing category field', async () => {
      const user = userEvent.setup();
      const onHasChanges = vi.fn();
      const existingCategory = makeCategory({ categoryId: 1, name: 'Category 1', description: 'Description 1' });
      render(<CategoryManagerForm {...defaultProps} category={existingCategory} onHasChanges={onHasChanges} />);

      // Initially no changes
      expect(onHasChanges).toHaveBeenCalledWith(false);

      await user.clear(screen.getByLabelText(/Name/));
      await user.type(screen.getByLabelText(/Name/), 'Changed Name');

      expect(onHasChanges).toHaveBeenCalledWith(true);
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

  describe('back link', () => {
    it('should render back link', () => {
      render(<CategoryManagerForm {...defaultProps} isNew={true} />);
      expect(screen.getByText('← Back to Categories')).toBeInTheDocument();
    });

    it('should call onBack when back link is clicked', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerForm {...defaultProps} isNew={true} />);
      await user.click(screen.getByText('← Back to Categories'));
      expect(defaultProps.onBack).toHaveBeenCalled();
    });
  });

  describe('initialName', () => {
    it('should pre-fill name field with initialName when in create mode', () => {
      render(<CategoryManagerForm {...defaultProps} isNew={true} initialName="Pre-filled" />);
      expect(screen.getByDisplayValue('Pre-filled')).toBeInTheDocument();
    });

    it('should not use initialName in edit mode', () => {
      const cat = makeCategory({ name: 'Existing' });
      render(<CategoryManagerForm {...defaultProps} category={cat} isNew={false} initialName="Pre-filled" />);
      expect(screen.getByDisplayValue('Existing')).toBeInTheDocument();
      expect(screen.queryByDisplayValue('Pre-filled')).not.toBeInTheDocument();
    });
  });

  // Footer (Delete/Cancel/Save) is rendered at the modal level, not inside the form
});
