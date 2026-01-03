import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import PropertyEditor from '../src/PropertyEditor';
import type { ItemProperty } from '../src/types';

describe('PropertyEditor', () => {
  const mockProperties: ItemProperty[] = [
    { category: 'General', name: 'Prop1', value: 'Value1' },
    { category: 'Technical', name: 'Prop2', value: 'Value2' },
  ];

  describe('snapshots', () => {
    it('should render with properties', () => {
      const { container } = render(
        <PropertyEditor properties={mockProperties} onChange={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });

    it('should render with empty properties', () => {
      const { container } = render(
        <PropertyEditor properties={[]} onChange={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });
  });

  describe('display', () => {
    it('should display all properties', () => {
      render(<PropertyEditor properties={mockProperties} onChange={() => {}} />);

      const categoryInputs = screen.getAllByPlaceholderText('Category');
      expect(categoryInputs.length).toBe(2);
      expect(categoryInputs[0]).toHaveValue('General');
      expect(categoryInputs[1]).toHaveValue('Technical');
    });

    it('should show add property button', () => {
      render(<PropertyEditor properties={[]} onChange={() => {}} />);

      expect(screen.getByText('+ Add Property')).toBeInTheDocument();
    });

    it('should show remove button for each property', () => {
      render(<PropertyEditor properties={mockProperties} onChange={() => {}} />);

      const removeButtons = screen.getAllByLabelText('Remove property');
      expect(removeButtons.length).toBe(2);
    });
  });

  describe('interactions', () => {
    it('should call onChange when adding a property', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      render(<PropertyEditor properties={mockProperties} onChange={handleChange} />);

      await user.click(screen.getByText('+ Add Property'));

      expect(handleChange).toHaveBeenCalledWith([
        ...mockProperties,
        { category: '', name: '', value: '' },
      ]);
    });

    it('should call onChange when removing a property', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      render(<PropertyEditor properties={mockProperties} onChange={handleChange} />);

      const removeButtons = screen.getAllByLabelText('Remove property');
      await user.click(removeButtons[0]);

      expect(handleChange).toHaveBeenCalledWith([mockProperties[1]]);
    });

    it('should call onChange when updating category', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      render(<PropertyEditor properties={mockProperties} onChange={handleChange} />);

      const categoryInputs = screen.getAllByPlaceholderText('Category');
      await user.clear(categoryInputs[0]);
      await user.type(categoryInputs[0], 'New Category');

      expect(handleChange).toHaveBeenCalled();
    });

    it('should call onChange when updating name', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      render(<PropertyEditor properties={mockProperties} onChange={handleChange} />);

      const nameInputs = screen.getAllByPlaceholderText('Name');
      await user.clear(nameInputs[0]);
      await user.type(nameInputs[0], 'New Name');

      expect(handleChange).toHaveBeenCalled();
    });

    it('should call onChange when updating value', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      render(<PropertyEditor properties={mockProperties} onChange={handleChange} />);

      const valueInputs = screen.getAllByPlaceholderText('Value');
      await user.clear(valueInputs[0]);
      await user.type(valueInputs[0], 'New Value');

      expect(handleChange).toHaveBeenCalled();
    });
  });
});

