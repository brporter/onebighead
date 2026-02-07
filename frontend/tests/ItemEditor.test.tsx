import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ItemEditor from '../src/components/item/ItemEditor';
import type { Item, Collection } from '../src/utils/types';
import { UserFlag, Visibility } from '../src/utils/types';

// Mock DataContext for PropertyEditor and ImageEditor
vi.mock('../src/contexts/DataContext', () => ({
  useData: () => ({
    propertyCategorySuggestions: [],
    propertyNameSuggestions: [],
    addLocalCategorySuggestion: vi.fn(),
    addLocalNameSuggestion: vi.fn(),
    uploadImage: vi.fn().mockResolvedValue({ key: 'test-key', url: '/api/images/test-key' }),
  }),
}));

describe('ItemEditor', () => {
  const mockItem: Item = {
    id: 1,
    workspaceId: 1,
    collectionId: 1,
    categoryId: 2,
    templateKey: null,
    name: 'Test Item',
    summary: 'Test summary',
    description: 'Test description',
    properties: [
      { category: 'General', name: 'Prop1', value: 'Value1' },
      { category: 'General', name: 'Prop2', value: 'Value2' },
      { category: 'Technical', name: 'Prop3', value: 'Value3' },
    ],
    images: [
      { url: 'https://example.com/image1.jpg', alt: 'Image 1' },
      { url: 'https://example.com/image2.jpg', alt: 'Image 2' },
    ],
    visibility: Visibility.Default,
    effectiveIsPublic: true,
    userFlag: UserFlag.None,
  };

  const mockCategories = [
    { workspaceId: 1, collectionId: 1, categoryId: 1, name: 'Category 1', description: 'Desc 1', parentCategoryId: null, isSystem: false, visibility: Visibility.Default, effectiveIsPublic: true, itemTemplateIds: [] },
    { workspaceId: 1, collectionId: 1, categoryId: 2, name: 'Category 2', description: 'Desc 2', parentCategoryId: null, isSystem: false, visibility: Visibility.Default, effectiveIsPublic: true, itemTemplateIds: [] },
  ];

  const mockCollection: Collection = {
    collectionId: 1,
    workspaceId: 1,
    name: 'Test Collection',
    description: 'Test description',
    heroImageUrl: null,
    slug: 'test-collection',
    visibility: Visibility.Private,
    effectiveIsPublic: false,
  };

  const defaultProps = {
    categories: mockCategories,
    collection: mockCollection,
    onSave: vi.fn(),
    onCancel: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('snapshots', () => {
    it('should render edit mode', () => {
      const { container } = render(<ItemEditor item={mockItem} {...defaultProps} />);
      expect(container).toMatchSnapshot();
    });

    it('should render new item mode', () => {
      const { container } = render(<ItemEditor item={null} {...defaultProps} />);
      expect(container).toMatchSnapshot();
    });
  });

  describe('edit mode', () => {
    it('should show form fields', () => {
      render(<ItemEditor item={mockItem} {...defaultProps} />);

      expect(screen.getByLabelText('Name')).toBeInTheDocument();
      expect(screen.getByLabelText('Summary')).toBeInTheDocument();
      expect(screen.getByLabelText('Description')).toBeInTheDocument();
    });

    it('should show edit title with item name', () => {
      render(<ItemEditor item={mockItem} {...defaultProps} />);

      expect(screen.getByText('Edit: Test Item')).toBeInTheDocument();
    });

    it('should prevent form submission', () => {
      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const form = document.querySelector('.detail__form');
      const submitEvent = new Event('submit', { bubbles: true, cancelable: true });
      form?.dispatchEvent(submitEvent);

      // Form submission should be prevented - no navigation or errors
      expect(screen.getByLabelText('Name')).toBeInTheDocument();
    });

    it('should populate form with item data', () => {
      render(<ItemEditor item={mockItem} {...defaultProps} />);

      expect(screen.getByLabelText('Name')).toHaveValue('Test Item');
      expect(screen.getByLabelText('Summary')).toHaveValue('Test summary');
      expect(screen.getByLabelText('Description')).toHaveValue('Test description');
    });

    it('should update form field values', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const nameInput = screen.getByLabelText('Name');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Name');

      expect(nameInput).toHaveValue('Updated Name');
    });

    it('should update description field', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const descriptionInput = screen.getByLabelText('Description');
      await user.clear(descriptionInput);
      await user.type(descriptionInput, 'Updated Description');

      expect(descriptionInput).toHaveValue('Updated Description');
    });

    it('should call onSave with updated data when clicking save', async () => {
      const user = userEvent.setup();
      const handleSave = vi.fn();

      render(<ItemEditor item={mockItem} categories={mockCategories} collection={mockCollection} onSave={handleSave} onCancel={vi.fn()} />);

      const nameInput = screen.getByLabelText('Name');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Name');

      await user.click(screen.getByText('Save Changes'));

      expect(handleSave).toHaveBeenCalledWith(expect.objectContaining({
        name: 'Updated Name',
      }));
    });

    it('should call onCancel when clicking cancel', async () => {
      const user = userEvent.setup();
      const handleCancel = vi.fn();

      render(<ItemEditor item={mockItem} categories={mockCategories} collection={mockCollection} onSave={vi.fn()} onCancel={handleCancel} />);

      await user.click(screen.getByText('Cancel'));

      expect(handleCancel).toHaveBeenCalled();
    });

    it('should disable save button when name is empty', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const nameInput = screen.getByLabelText('Name');
      await user.clear(nameInput);

      expect(screen.getByText('Save Changes')).toBeDisabled();
    });

    it('should show delete button when onDelete is provided', () => {
      render(<ItemEditor item={mockItem} {...defaultProps} onDelete={() => {}} />);

      expect(screen.getByText('Delete')).toBeInTheDocument();
    });

    it('should call onDelete after confirmation', async () => {
      const user = userEvent.setup();
      const handleDelete = vi.fn();
      vi.spyOn(window, 'confirm').mockReturnValue(true);

      render(<ItemEditor item={mockItem} {...defaultProps} onDelete={handleDelete} />);

      await user.click(screen.getByText('Delete'));

      expect(handleDelete).toHaveBeenCalledWith(1);
    });

    it('should not call onDelete if confirmation is cancelled', async () => {
      const user = userEvent.setup();
      const handleDelete = vi.fn();
      vi.spyOn(window, 'confirm').mockReturnValue(false);

      render(<ItemEditor item={mockItem} {...defaultProps} onDelete={handleDelete} />);

      await user.click(screen.getByText('Delete'));

      expect(handleDelete).not.toHaveBeenCalled();
    });
  });

  describe('new item mode', () => {
    it('should show form fields', () => {
      render(<ItemEditor item={null} {...defaultProps} />);

      expect(screen.getByLabelText('Name')).toBeInTheDocument();
    });

    it('should show "Add New Item" title', () => {
      render(<ItemEditor item={null} {...defaultProps} />);

      expect(screen.getByText('Add New Item')).toBeInTheDocument();
    });

    it('should show "Create Item" button', () => {
      render(<ItemEditor item={null} {...defaultProps} />);

      expect(screen.getByText('Create Item')).toBeInTheDocument();
    });

    it('should not show delete button', () => {
      render(<ItemEditor item={null} {...defaultProps} onDelete={() => {}} />);

      expect(screen.queryByText('Delete')).not.toBeInTheDocument();
    });

    it('should call onCancel when clicking cancel', async () => {
      const user = userEvent.setup();
      const handleCancel = vi.fn();

      render(<ItemEditor item={null} categories={mockCategories} collection={mockCollection} onSave={vi.fn()} onCancel={handleCancel} />);

      await user.click(screen.getByText('Cancel'));

      expect(handleCancel).toHaveBeenCalled();
    });

    it('should call onSave with new item data', async () => {
      const user = userEvent.setup();
      const handleSave = vi.fn();

      render(<ItemEditor item={null} categories={mockCategories} collection={mockCollection} onSave={handleSave} onCancel={vi.fn()} />);

      await user.type(screen.getByLabelText('Name'), 'New Item');
      await user.type(screen.getByLabelText('Summary'), 'New summary');
      await user.click(screen.getByText('Create Item'));

      expect(handleSave).toHaveBeenCalledWith(expect.objectContaining({
        name: 'New Item',
        summary: 'New summary',
      }));
    });
  });

  describe('property editor', () => {
    it('should display existing properties', () => {
      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const categoryInputs = screen.getAllByPlaceholderText('Category');
      expect(categoryInputs.length).toBe(3);
    });

    it('should add new property', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const initialPropertyRows = screen.getAllByPlaceholderText('Category').length;

      await user.click(screen.getByText('+ Add Property'));

      const newPropertyRows = screen.getAllByPlaceholderText('Category').length;
      expect(newPropertyRows).toBe(initialPropertyRows + 1);
    });

    it('should remove property', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const initialPropertyRows = screen.getAllByPlaceholderText('Category').length;

      const removeButtons = screen.getAllByLabelText('Remove property');
      await user.click(removeButtons[0]);

      const newPropertyRows = screen.getAllByPlaceholderText('Category').length;
      expect(newPropertyRows).toBe(initialPropertyRows - 1);
    });

    it('should update property category field', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const categoryInputs = screen.getAllByPlaceholderText('Category');
      await user.clear(categoryInputs[0]);
      await user.type(categoryInputs[0], 'New Category');

      expect(categoryInputs[0]).toHaveValue('New Category');
    });

    it('should update property name field', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const nameInputs = screen.getAllByPlaceholderText('Name');
      // First one is the item name, so we need to skip it
      const propertyNameInputs = nameInputs.filter(input =>
        input.closest('.propertyEditor__row')
      );
      await user.clear(propertyNameInputs[0]);
      await user.type(propertyNameInputs[0], 'New Prop Name');

      expect(propertyNameInputs[0]).toHaveValue('New Prop Name');
    });

    it('should update property value field', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const valueInputs = screen.getAllByPlaceholderText('Value');
      await user.clear(valueInputs[0]);
      await user.type(valueInputs[0], 'New Value');

      expect(valueInputs[0]).toHaveValue('New Value');
    });
  });

  describe('image editor', () => {
    it('should display existing images', () => {
      render(<ItemEditor item={mockItem} {...defaultProps} />);

      // With file upload, images are shown as img elements not URL inputs
      const images = screen.getAllByRole('img');
      expect(images.length).toBe(2);
    });

    it('should add new image via file upload', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const initialImages = screen.getAllByRole('img').length;

      // Simulate file upload
      const file = new File(['content'], 'new-image.jpg', { type: 'image/jpeg' });
      const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
      await user.upload(fileInput, file);

      await waitFor(() => {
        const newImages = screen.getAllByRole('img').length;
        expect(newImages).toBe(initialImages + 1);
      });
    });

    it('should remove image', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const initialImages = screen.getAllByRole('img').length;

      const removeButtons = screen.getAllByLabelText('Remove image');
      await user.click(removeButtons[0]);

      const newImages = screen.getAllByRole('img').length;
      expect(newImages).toBe(initialImages - 1);
    });

    it('should update image alt field', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const altInputs = screen.getAllByPlaceholderText('Alt text');
      await user.clear(altInputs[0]);
      await user.type(altInputs[0], 'New alt text');

      expect(altInputs[0]).toHaveValue('New alt text');
    });

    it('should have file input for uploading images', () => {
      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const fileInput = document.querySelector('input[type="file"]');
      expect(fileInput).toBeInTheDocument();
      expect(fileInput).toHaveAttribute('accept', 'image/jpeg,image/png,image/gif,image/webp');
    });
  });

  describe('user flag selector', () => {
    it('should display the relationship fieldset', () => {
      render(<ItemEditor item={mockItem} {...defaultProps} />);

      expect(screen.getByText('My Relationship to This Item')).toBeInTheDocument();
    });

    it('should display all flag options', () => {
      render(<ItemEditor item={mockItem} {...defaultProps} />);

      expect(screen.getByText('None')).toBeInTheDocument();
      expect(screen.getByText('I Have This')).toBeInTheDocument();
      expect(screen.getByText('I Want This')).toBeInTheDocument();
      expect(screen.getByText('For Trade/Sale')).toBeInTheDocument();
    });

    it('should have None selected by default', () => {
      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const noneRadio = screen.getByRole('radio', { name: 'None' });
      expect(noneRadio).toBeChecked();
    });

    it('should select Have flag', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const haveRadio = screen.getByRole('radio', { name: 'I Have This' });
      await user.click(haveRadio);

      expect(haveRadio).toBeChecked();
    });

    it('should select Want flag', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const wantRadio = screen.getByRole('radio', { name: 'I Want This' });
      await user.click(wantRadio);

      expect(wantRadio).toBeChecked();
    });

    it('should select TradeOrSell flag', async () => {
      const user = userEvent.setup();

      render(<ItemEditor item={mockItem} {...defaultProps} />);

      const tradeRadio = screen.getByRole('radio', { name: 'For Trade/Sale' });
      await user.click(tradeRadio);

      expect(tradeRadio).toBeChecked();
    });

    it('should include userFlag in saved data', async () => {
      const user = userEvent.setup();
      const handleSave = vi.fn();

      render(<ItemEditor item={mockItem} categories={mockCategories} collection={mockCollection} onSave={handleSave} onCancel={vi.fn()} />);

      const wantRadio = screen.getByRole('radio', { name: 'I Want This' });
      await user.click(wantRadio);

      await user.click(screen.getByText('Save Changes'));

      expect(handleSave).toHaveBeenCalledWith(expect.objectContaining({
        userFlag: UserFlag.Want,
      }));
    });

    it('should preserve existing userFlag from item', () => {
      const itemWithFlag = { ...mockItem, userFlag: UserFlag.TradeOrSell };
      render(<ItemEditor item={itemWithFlag} {...defaultProps} />);

      const tradeRadio = screen.getByRole('radio', { name: 'For Trade/Sale' });
      expect(tradeRadio).toBeChecked();
    });

    it('should change flag from Have to Want and save', async () => {
      const user = userEvent.setup();
      const handleSave = vi.fn();
      const itemWithHaveFlag = { ...mockItem, userFlag: UserFlag.Have };

      render(<ItemEditor item={itemWithHaveFlag} categories={mockCategories} collection={mockCollection} onSave={handleSave} onCancel={vi.fn()} />);

      // Verify initial state
      expect(screen.getByRole('radio', { name: 'I Have This' })).toBeChecked();

      // Change to Want
      const wantRadio = screen.getByRole('radio', { name: 'I Want This' });
      await user.click(wantRadio);

      expect(wantRadio).toBeChecked();

      await user.click(screen.getByText('Save Changes'));

      expect(handleSave).toHaveBeenCalledWith(expect.objectContaining({
        userFlag: UserFlag.Want,
      }));
    });

    it('should include userFlag in new item creation', async () => {
      const user = userEvent.setup();
      const handleSave = vi.fn();

      render(<ItemEditor item={null} categories={mockCategories} collection={mockCollection} onSave={handleSave} onCancel={vi.fn()} />);

      // Fill required fields
      await user.type(screen.getByLabelText('Name'), 'New Item');

      // Select a flag
      const tradeRadio = screen.getByRole('radio', { name: 'For Trade/Sale' });
      await user.click(tradeRadio);

      await user.click(screen.getByText('Create Item'));

      expect(handleSave).toHaveBeenCalledWith(expect.objectContaining({
        name: 'New Item',
        userFlag: UserFlag.TradeOrSell,
      }));
    });

    it('should default to None flag for new items', async () => {
      const user = userEvent.setup();
      const handleSave = vi.fn();

      render(<ItemEditor item={null} categories={mockCategories} collection={mockCollection} onSave={handleSave} onCancel={vi.fn()} />);

      // Verify None is checked by default
      expect(screen.getByRole('radio', { name: 'None' })).toBeChecked();

      // Fill required fields and save without changing flag
      await user.type(screen.getByLabelText('Name'), 'New Item Without Flag');
      await user.click(screen.getByText('Create Item'));

      expect(handleSave).toHaveBeenCalledWith(expect.objectContaining({
        userFlag: UserFlag.None,
      }));
    });

    it('should render snapshot with user flag selector', () => {
      const { container } = render(<ItemEditor item={mockItem} {...defaultProps} />);
      expect(container).toMatchSnapshot();
    });

    it('should render snapshot for new item with user flag selector', () => {
      const { container } = render(<ItemEditor item={null} {...defaultProps} />);
      expect(container).toMatchSnapshot();
    });

    it('should render snapshot with Have flag selected', () => {
      const itemWithFlag = { ...mockItem, userFlag: UserFlag.Have };
      const { container } = render(<ItemEditor item={itemWithFlag} {...defaultProps} />);
      expect(container).toMatchSnapshot();
    });

    it('should render snapshot with Want flag selected', () => {
      const itemWithFlag = { ...mockItem, userFlag: UserFlag.Want };
      const { container } = render(<ItemEditor item={itemWithFlag} {...defaultProps} />);
      expect(container).toMatchSnapshot();
    });
  });
});

