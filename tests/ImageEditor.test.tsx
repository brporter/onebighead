import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ImageEditor from '../src/ImageEditor';
import type { ItemImage } from '../src/types';

describe('ImageEditor', () => {
  const mockImages: ItemImage[] = [
    { url: 'https://example.com/image1.jpg', alt: 'Image 1' },
    { url: 'https://example.com/image2.jpg', alt: 'Image 2' },
  ];

  describe('snapshots', () => {
    it('should render with images', () => {
      const { container } = render(
        <ImageEditor images={mockImages} onChange={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });

    it('should render with empty images', () => {
      const { container } = render(
        <ImageEditor images={[]} onChange={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });
  });

  describe('display', () => {
    it('should display all images', () => {
      render(<ImageEditor images={mockImages} onChange={() => {}} />);

      const urlInputs = screen.getAllByPlaceholderText('Image URL');
      expect(urlInputs.length).toBe(2);
      expect(urlInputs[0]).toHaveValue('https://example.com/image1.jpg');
      expect(urlInputs[1]).toHaveValue('https://example.com/image2.jpg');
    });

    it('should show add image button', () => {
      render(<ImageEditor images={[]} onChange={() => {}} />);

      expect(screen.getByText('+ Add Image')).toBeInTheDocument();
    });

    it('should show remove button for each image', () => {
      render(<ImageEditor images={mockImages} onChange={() => {}} />);

      const removeButtons = screen.getAllByLabelText('Remove image');
      expect(removeButtons.length).toBe(2);
    });
  });

  describe('interactions', () => {
    it('should call onChange when adding an image', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      render(<ImageEditor images={mockImages} onChange={handleChange} />);

      await user.click(screen.getByText('+ Add Image'));

      expect(handleChange).toHaveBeenCalledWith([
        ...mockImages,
        { url: '', alt: '' },
      ]);
    });

    it('should call onChange when removing an image', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      render(<ImageEditor images={mockImages} onChange={handleChange} />);

      const removeButtons = screen.getAllByLabelText('Remove image');
      await user.click(removeButtons[0]);

      expect(handleChange).toHaveBeenCalledWith([mockImages[1]]);
    });

    it('should call onChange when updating URL', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      render(<ImageEditor images={mockImages} onChange={handleChange} />);

      const urlInputs = screen.getAllByPlaceholderText('Image URL');
      await user.clear(urlInputs[0]);
      await user.type(urlInputs[0], 'https://new-url.com/image.jpg');

      expect(handleChange).toHaveBeenCalled();
    });

    it('should call onChange when updating alt text', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      render(<ImageEditor images={mockImages} onChange={handleChange} />);

      const altInputs = screen.getAllByPlaceholderText('Alt text');
      await user.clear(altInputs[0]);
      await user.type(altInputs[0], 'New alt text');

      expect(handleChange).toHaveBeenCalled();
    });
  });
});

