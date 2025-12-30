import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ItemDetail from '../src/ItemDetail';
import type { Item } from '../src/types';

describe('ItemDetail', () => {
  const mockItem: Item = {
    id: 1,
    tenantId: 1,
    categoryId: 2,
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
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('snapshots', () => {
    it('should render empty state', () => {
      const { container } = render(<ItemDetail item={null} />);
      expect(container).toMatchSnapshot();
    });

    it('should render view mode', () => {
      const { container } = render(<ItemDetail item={mockItem} />);
      expect(container).toMatchSnapshot();
    });

    it('should render edit mode', () => {
      const { container } = render(<ItemDetail item={mockItem} isNew={false} />);
      // Click edit to enter edit mode
      const editButton = container.querySelector('.detail__btn--secondary');
      if (editButton) {
        editButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      }
      expect(container).toMatchSnapshot();
    });

    it('should render new item mode', () => {
      const { container } = render(<ItemDetail item={null} isNew={true} />);
      expect(container).toMatchSnapshot();
    });

    it('should render item without properties', () => {
      const itemWithoutProps = { ...mockItem, properties: [] };
      const { container } = render(<ItemDetail item={itemWithoutProps} />);
      expect(container).toMatchSnapshot();
    });

    it('should render item without images', () => {
      const itemWithoutImages = { ...mockItem, images: [] };
      const { container } = render(<ItemDetail item={itemWithoutImages} />);
      expect(container).toMatchSnapshot();
    });
  });

  describe('view mode', () => {
    it('should show placeholder when no item selected', () => {
      render(<ItemDetail item={null} />);

      expect(screen.getByText('Select an item')).toBeInTheDocument();
    });

    it('should display item name', () => {
      render(<ItemDetail item={mockItem} />);

      expect(screen.getByText('Test Item')).toBeInTheDocument();
    });

    it('should display item description', () => {
      render(<ItemDetail item={mockItem} />);

      expect(screen.getByText('Test description')).toBeInTheDocument();
    });

    it('should display properties grouped by category', () => {
      render(<ItemDetail item={mockItem} />);

      expect(screen.getByText('General')).toBeInTheDocument();
      expect(screen.getByText('Technical')).toBeInTheDocument();
      expect(screen.getByText('Prop1')).toBeInTheDocument();
      expect(screen.getByText('Value1')).toBeInTheDocument();
    });

    it('should group properties without category under Other', () => {
      const itemWithUncategorizedProps: Item = {
        ...mockItem,
        properties: [
          { category: '', name: 'Uncategorized', value: 'Value' },
          { category: '   ', name: 'Whitespace', value: 'Value2' },
        ],
      };

      render(<ItemDetail item={itemWithUncategorizedProps} />);

      expect(screen.getByText('Other')).toBeInTheDocument();
      expect(screen.getByText('Uncategorized')).toBeInTheDocument();
    });

    it('should show edit button', () => {
      render(<ItemDetail item={mockItem} />);

      expect(screen.getByText('Edit')).toBeInTheDocument();
    });

    it('should show back button when onClose is provided', () => {
      render(<ItemDetail item={mockItem} onClose={() => {}} />);

      expect(screen.getByText('Back to list')).toBeInTheDocument();
    });

    it('should call onClose when clicking back button', async () => {
      const user = userEvent.setup();
      const handleClose = vi.fn();

      render(<ItemDetail item={mockItem} onClose={handleClose} />);

      await user.click(screen.getByText('Back to list'));

      expect(handleClose).toHaveBeenCalled();
    });

    it('should enter edit mode when clicking edit button', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);

      await user.click(screen.getByText('Edit'));

      expect(screen.getByLabelText('Name')).toBeInTheDocument();
    });
  });

  describe('edit mode', () => {
    it('should show form fields', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      expect(screen.getByLabelText('Name')).toBeInTheDocument();
      expect(screen.getByLabelText('Summary')).toBeInTheDocument();
      expect(screen.getByLabelText('Description')).toBeInTheDocument();
    });

    it('should show edit title with item name', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      expect(screen.getByText('Edit: Test Item')).toBeInTheDocument();
    });

    it('should prevent form submission', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const form = document.querySelector('.detail__form');
      const submitEvent = new Event('submit', { bubbles: true, cancelable: true });
      form?.dispatchEvent(submitEvent);

      // Form submission should be prevented - no navigation or errors
      expect(screen.getByLabelText('Name')).toBeInTheDocument();
    });

    it('should populate form with item data', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      expect(screen.getByLabelText('Name')).toHaveValue('Test Item');
      expect(screen.getByLabelText('Summary')).toHaveValue('Test summary');
      expect(screen.getByLabelText('Description')).toHaveValue('Test description');
    });

    it('should update form field values', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const nameInput = screen.getByLabelText('Name');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Name');

      expect(nameInput).toHaveValue('Updated Name');
    });

    it('should update description field', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const descriptionInput = screen.getByLabelText('Description');
      await user.clear(descriptionInput);
      await user.type(descriptionInput, 'Updated Description');

      expect(descriptionInput).toHaveValue('Updated Description');
    });

    it('should call onSave with updated data when clicking save', async () => {
      const user = userEvent.setup();
      const handleSave = vi.fn();

      render(<ItemDetail item={mockItem} onSave={handleSave} />);
      await user.click(screen.getByText('Edit'));

      const nameInput = screen.getByLabelText('Name');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Name');

      await user.click(screen.getByText('Save Changes'));

      expect(handleSave).toHaveBeenCalledWith(expect.objectContaining({
        name: 'Updated Name',
      }));
    });

    it('should exit edit mode after saving', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} onSave={() => {}} />);
      await user.click(screen.getByText('Edit'));
      await user.click(screen.getByText('Save Changes'));

      expect(screen.queryByLabelText('Name')).not.toBeInTheDocument();
    });

    it('should cancel edit and restore original data', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const nameInput = screen.getByLabelText('Name');
      await user.clear(nameInput);
      await user.type(nameInput, 'Modified Name');

      await user.click(screen.getByText('Cancel'));

      // Should exit edit mode and show original name
      expect(screen.getByRole('heading', { name: 'Test Item' })).toBeInTheDocument();
    });

    it('should disable save button when name is empty', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const nameInput = screen.getByLabelText('Name');
      await user.clear(nameInput);

      expect(screen.getByText('Save Changes')).toBeDisabled();
    });

    it('should show delete button when onDelete is provided', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} onDelete={() => {}} />);
      await user.click(screen.getByText('Edit'));

      expect(screen.getByText('Delete')).toBeInTheDocument();
    });

    it('should call onDelete after confirmation', async () => {
      const user = userEvent.setup();
      const handleDelete = vi.fn();
      vi.spyOn(window, 'confirm').mockReturnValue(true);

      render(<ItemDetail item={mockItem} onDelete={handleDelete} />);
      await user.click(screen.getByText('Edit'));
      await user.click(screen.getByText('Delete'));

      expect(handleDelete).toHaveBeenCalledWith(1);
    });

    it('should not call onDelete if confirmation is cancelled', async () => {
      const user = userEvent.setup();
      const handleDelete = vi.fn();
      vi.spyOn(window, 'confirm').mockReturnValue(false);

      render(<ItemDetail item={mockItem} onDelete={handleDelete} />);
      await user.click(screen.getByText('Edit'));
      await user.click(screen.getByText('Delete'));

      expect(handleDelete).not.toHaveBeenCalled();
    });
  });

  describe('new item mode', () => {
    it('should start in edit mode', () => {
      render(<ItemDetail item={null} isNew={true} />);

      expect(screen.getByLabelText('Name')).toBeInTheDocument();
    });

    it('should show "Add New Item" title', () => {
      render(<ItemDetail item={null} isNew={true} />);

      expect(screen.getByText('Add New Item')).toBeInTheDocument();
    });

    it('should show "Create Item" button', () => {
      render(<ItemDetail item={null} isNew={true} />);

      expect(screen.getByText('Create Item')).toBeInTheDocument();
    });

    it('should not show delete button', () => {
      render(<ItemDetail item={null} isNew={true} onDelete={() => {}} />);

      expect(screen.queryByText('Delete')).not.toBeInTheDocument();
    });

    it('should call onClose when cancelling new item', async () => {
      const user = userEvent.setup();
      const handleClose = vi.fn();

      render(<ItemDetail item={null} isNew={true} onClose={handleClose} />);

      await user.click(screen.getByText('Cancel'));

      expect(handleClose).toHaveBeenCalled();
    });

    it('should call onSave with new item data', async () => {
      const user = userEvent.setup();
      const handleSave = vi.fn();

      render(<ItemDetail item={null} isNew={true} onSave={handleSave} />);

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
    it('should display existing properties in edit mode', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const categoryInputs = screen.getAllByPlaceholderText('Category');
      expect(categoryInputs.length).toBe(3);
    });

    it('should add new property', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const initialPropertyRows = screen.getAllByPlaceholderText('Category').length;

      await user.click(screen.getByText('+ Add Property'));

      const newPropertyRows = screen.getAllByPlaceholderText('Category').length;
      expect(newPropertyRows).toBe(initialPropertyRows + 1);
    });

    it('should remove property', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const initialPropertyRows = screen.getAllByPlaceholderText('Category').length;

      const removeButtons = screen.getAllByLabelText('Remove property');
      await user.click(removeButtons[0]);

      const newPropertyRows = screen.getAllByPlaceholderText('Category').length;
      expect(newPropertyRows).toBe(initialPropertyRows - 1);
    });

    it('should update property category field', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const categoryInputs = screen.getAllByPlaceholderText('Category');
      await user.clear(categoryInputs[0]);
      await user.type(categoryInputs[0], 'New Category');

      expect(categoryInputs[0]).toHaveValue('New Category');
    });

    it('should update property name field', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

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

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const valueInputs = screen.getAllByPlaceholderText('Value');
      await user.clear(valueInputs[0]);
      await user.type(valueInputs[0], 'New Value');

      expect(valueInputs[0]).toHaveValue('New Value');
    });
  });

  describe('image editor', () => {
    it('should display existing images in edit mode', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const urlInputs = screen.getAllByPlaceholderText('Image URL');
      expect(urlInputs.length).toBe(2);
    });

    it('should add new image', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const initialImageRows = screen.getAllByPlaceholderText('Image URL').length;

      await user.click(screen.getByText('+ Add Image'));

      const newImageRows = screen.getAllByPlaceholderText('Image URL').length;
      expect(newImageRows).toBe(initialImageRows + 1);
    });

    it('should remove image', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const initialImageRows = screen.getAllByPlaceholderText('Image URL').length;

      const removeButtons = screen.getAllByLabelText('Remove image');
      await user.click(removeButtons[0]);

      const newImageRows = screen.getAllByPlaceholderText('Image URL').length;
      expect(newImageRows).toBe(initialImageRows - 1);
    });

    it('should update image URL field', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const urlInputs = screen.getAllByPlaceholderText('Image URL');
      await user.clear(urlInputs[0]);
      await user.type(urlInputs[0], 'https://new-url.com/image.jpg');

      expect(urlInputs[0]).toHaveValue('https://new-url.com/image.jpg');
    });

    it('should update image alt field', async () => {
      const user = userEvent.setup();

      render(<ItemDetail item={mockItem} />);
      await user.click(screen.getByText('Edit'));

      const altInputs = screen.getAllByPlaceholderText('Alt text');
      await user.clear(altInputs[0]);
      await user.type(altInputs[0], 'New alt text');

      expect(altInputs[0]).toHaveValue('New alt text');
    });
  });
});

