import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ImageEditor from '../src/components/common/ImageEditor';
import { DataProvider } from '../src/contexts/DataContext';
import type { ItemImage } from '../src/utils/types';

// Mock fetch for image upload
const mockFetch = vi.fn();

describe('ImageEditor', () => {
  const mockImages: ItemImage[] = [
    { url: '/api/images/abc-123', alt: 'Image 1' },
    { url: '/api/images/def-456', alt: 'Image 2' },
  ];

  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch);
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const renderWithProvider = (ui: React.ReactElement) => {
    return render(
      <DataProvider>
        {ui}
      </DataProvider>
    );
  };

  describe('snapshots', () => {
    it('should render with images', () => {
      const { container } = renderWithProvider(
        <ImageEditor images={mockImages} onChange={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });

    it('should render with empty images', () => {
      const { container } = renderWithProvider(
        <ImageEditor images={[]} onChange={() => {}} />
      );
      expect(container).toMatchSnapshot();
    });
  });

  describe('display', () => {
    it('should display all images with previews', () => {
      renderWithProvider(<ImageEditor images={mockImages} onChange={() => {}} />);

      const images = screen.getAllByRole('img');
      expect(images.length).toBe(2);
      expect(images[0]).toHaveAttribute('src', '/api/images/abc-123');
      expect(images[1]).toHaveAttribute('src', '/api/images/def-456');
    });

    it('should show add image button', () => {
      renderWithProvider(<ImageEditor images={[]} onChange={() => {}} />);

      expect(screen.getByText('+ Add Image')).toBeInTheDocument();
    });

    it('should show remove button for each image', () => {
      renderWithProvider(<ImageEditor images={mockImages} onChange={() => {}} />);

      const removeButtons = screen.getAllByLabelText('Remove image');
      expect(removeButtons.length).toBe(2);
    });

    it('should display alt text inputs for each image', () => {
      renderWithProvider(<ImageEditor images={mockImages} onChange={() => {}} />);

      const altInputs = screen.getAllByPlaceholderText('Alt text');
      expect(altInputs.length).toBe(2);
      expect(altInputs[0]).toHaveValue('Image 1');
      expect(altInputs[1]).toHaveValue('Image 2');
    });
  });

  describe('interactions', () => {
    it('should call onChange when removing an image', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      renderWithProvider(<ImageEditor images={mockImages} onChange={handleChange} />);

      const removeButtons = screen.getAllByLabelText('Remove image');
      await user.click(removeButtons[0]);

      expect(handleChange).toHaveBeenCalledWith([mockImages[1]]);
    });

    it('should call onChange when updating alt text', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      renderWithProvider(<ImageEditor images={mockImages} onChange={handleChange} />);

      const altInputs = screen.getAllByPlaceholderText('Alt text');
      await user.clear(altInputs[0]);
      await user.type(altInputs[0], 'New alt text');

      expect(handleChange).toHaveBeenCalled();
    });

    it('should have hidden file input', () => {
      renderWithProvider(<ImageEditor images={[]} onChange={() => {}} />);

      const fileInput = document.querySelector('input[type="file"]');
      expect(fileInput).toBeInTheDocument();
      expect(fileInput).toHaveClass('imageEditor__fileInput');
    });

    it('should accept only allowed image types', () => {
      renderWithProvider(<ImageEditor images={[]} onChange={() => {}} />);

      const fileInput = document.querySelector('input[type="file"]');
      expect(fileInput).toHaveAttribute('accept', 'image/jpeg,image/png,image/gif,image/webp');
    });

    it('should allow multiple file selection', () => {
      renderWithProvider(<ImageEditor images={[]} onChange={() => {}} />);

      const fileInput = document.querySelector('input[type="file"]');
      expect(fileInput).toHaveAttribute('multiple');
    });
  });

  describe('file upload', () => {
    it('should upload file and call onChange with new image', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();
      const imageKey = 'new-image-key';

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ key: imageKey, url: `/api/images/${imageKey}` }),
      });

      renderWithProvider(<ImageEditor images={[]} onChange={handleChange} />);

      const file = new File(['fake image content'], 'test.jpg', { type: 'image/jpeg' });
      const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;

      await user.upload(fileInput, file);

      await waitFor(() => {
        expect(handleChange).toHaveBeenCalledWith([
          { url: `/api/images/${imageKey}`, alt: 'test' }
        ]);
      });
    });

    it('should upload multiple files', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ key: 'key1', url: '/api/images/key1' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ key: 'key2', url: '/api/images/key2' }),
        });

      renderWithProvider(<ImageEditor images={[]} onChange={handleChange} />);

      const files = [
        new File(['content1'], 'image1.jpg', { type: 'image/jpeg' }),
        new File(['content2'], 'image2.png', { type: 'image/png' }),
      ];
      const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;

      await user.upload(fileInput, files);

      await waitFor(() => {
        expect(handleChange).toHaveBeenCalledWith([
          { url: '/api/images/key1', alt: 'image1' },
          { url: '/api/images/key2', alt: 'image2' },
        ]);
      });
    });

    it('should append to existing images', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();
      const existingImages = [{ url: '/api/images/existing', alt: 'Existing' }];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ key: 'new-key', url: '/api/images/new-key' }),
      });

      renderWithProvider(<ImageEditor images={existingImages} onChange={handleChange} />);

      const file = new File(['content'], 'new.jpg', { type: 'image/jpeg' });
      const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;

      await user.upload(fileInput, file);

      await waitFor(() => {
        expect(handleChange).toHaveBeenCalledWith([
          ...existingImages,
          { url: '/api/images/new-key', alt: 'new' },
        ]);
      });
    });

    it('should display error message on upload failure', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: async () => JSON.stringify({ error: 'File type not allowed' }),
      });

      renderWithProvider(<ImageEditor images={[]} onChange={handleChange} />);

      const file = new File(['content'], 'test.jpg', { type: 'image/jpeg' });
      const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;

      await user.upload(fileInput, file);

      await waitFor(() => {
        expect(screen.getByText('File type not allowed')).toBeInTheDocument();
      });

      expect(handleChange).not.toHaveBeenCalled();
    });

    it('should show uploading state', async () => {
      const user = userEvent.setup();
      let resolveUpload: (value: unknown) => void;
      const uploadPromise = new Promise((resolve) => {
        resolveUpload = resolve;
      });

      mockFetch.mockReturnValueOnce(uploadPromise);

      renderWithProvider(<ImageEditor images={[]} onChange={() => {}} />);

      const file = new File(['content'], 'test.jpg', { type: 'image/jpeg' });
      const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;

      // Start upload
      user.upload(fileInput, file);

      await waitFor(() => {
        expect(screen.getByText('Uploading...')).toBeInTheDocument();
      });

      // Complete upload
      resolveUpload!({
        ok: true,
        json: async () => ({ key: 'key', url: '/api/images/key' }),
      });

      await waitFor(() => {
        expect(screen.getByText('+ Add Image')).toBeInTheDocument();
      });
    });

    it('should disable add button while uploading', async () => {
      const user = userEvent.setup();
      let resolveUpload: (value: unknown) => void;
      const uploadPromise = new Promise((resolve) => {
        resolveUpload = resolve;
      });

      mockFetch.mockReturnValueOnce(uploadPromise);

      renderWithProvider(<ImageEditor images={[]} onChange={() => {}} />);

      const file = new File(['content'], 'test.jpg', { type: 'image/jpeg' });
      const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;

      user.upload(fileInput, file);

      await waitFor(() => {
        const addButton = screen.getByText('Uploading...');
        expect(addButton).toBeDisabled();
      });

      resolveUpload!({
        ok: true,
        json: async () => ({ key: 'key', url: '/api/images/key' }),
      });
    });

    it('should strip file extension from alt text', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ key: 'key', url: '/api/images/key' }),
      });

      renderWithProvider(<ImageEditor images={[]} onChange={handleChange} />);

      const file = new File(['content'], 'my-photo.jpeg', { type: 'image/jpeg' });
      const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;

      await user.upload(fileInput, file);

      await waitFor(() => {
        expect(handleChange).toHaveBeenCalledWith([
          { url: '/api/images/key', alt: 'my-photo' },
        ]);
      });
    });
  });
});

