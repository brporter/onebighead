import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ImageGallery from '../src/ImageGallery';

describe('ImageGallery', () => {
  describe('snapshots', () => {
    it('should render nothing when images array is empty', () => {
      const { container } = render(<ImageGallery images={[]} />);
      expect(container).toMatchSnapshot();
    });

    it('should render nothing when images is undefined', () => {
      const { container } = render(<ImageGallery />);
      expect(container).toMatchSnapshot();
    });

    it('should render single image without navigation controls', () => {
      const { container } = render(
        <ImageGallery
          images={[{ url: 'https://example.com/image1.jpg', alt: 'Test image' }]}
          title="Test Gallery"
        />
      );
      expect(container).toMatchSnapshot();
    });

    it('should render multiple images with navigation controls', () => {
      const { container } = render(
        <ImageGallery
          images={[
            { url: 'https://example.com/image1.jpg', alt: 'Image 1' },
            { url: 'https://example.com/image2.jpg', alt: 'Image 2' },
          ]}
          title="Multi Image Gallery"
        />
      );
      expect(container).toMatchSnapshot();
    });

    it('should handle mixed string and object images', () => {
      const { container } = render(
        <ImageGallery
          images={[
            'https://example.com/string-image.jpg',
            { url: 'https://example.com/object-image.jpg', alt: 'Object image' },
          ]}
          title="Mixed Images"
        />
      );
      expect(container).toMatchSnapshot();
    });

    it('should handle image object with undefined alt', () => {
      const imagesWithUndefinedAlt = [
        { url: 'https://example.com/image.jpg' } as { url: string; alt?: string },
      ];

      const { container } = render(
        <ImageGallery
          images={imagesWithUndefinedAlt as Array<{ url: string; alt: string }>}
          title="Test"
        />
      );
      expect(container).toMatchSnapshot();
    });
  });

  describe('functionality', () => {
    it('should return null for empty images', () => {
      const { container } = render(<ImageGallery images={[]} />);
      expect(container.firstChild).toBeNull();
    });

    it('should filter out invalid images', () => {
      const { container } = render(
        <ImageGallery
          images={[
            { url: '', alt: 'Empty URL' },
            { url: '   ', alt: 'Whitespace URL' },
            { url: 'https://example.com/valid.jpg', alt: 'Valid' },
          ]}
        />
      );
      expect(screen.getByRole('img')).toHaveAttribute('src', 'https://example.com/valid.jpg');
      expect(container.querySelector('.gallery__controls')).toBeNull();
    });

    it('should display current image', () => {
      render(
        <ImageGallery
          images={[{ url: 'https://example.com/image.jpg', alt: 'Test alt' }]}
          title="Test"
        />
      );

      const img = screen.getByRole('img');
      expect(img).toHaveAttribute('src', 'https://example.com/image.jpg');
      expect(img).toHaveAttribute('alt', 'Test alt');
    });

    it('should use title as alt when image alt is empty', () => {
      render(
        <ImageGallery
          images={[{ url: 'https://example.com/image.jpg', alt: '' }]}
          title="Gallery Title"
        />
      );

      expect(screen.getByRole('img')).toHaveAttribute('alt', 'Gallery Title');
    });

    it('should navigate to next image', async () => {
      const user = userEvent.setup();
      render(
        <ImageGallery
          images={[
            { url: 'https://example.com/image1.jpg', alt: 'Image 1' },
            { url: 'https://example.com/image2.jpg', alt: 'Image 2' },
          ]}
        />
      );

      expect(screen.getByRole('img')).toHaveAttribute('src', 'https://example.com/image1.jpg');
      expect(screen.getByText('1 / 2')).toBeInTheDocument();

      await user.click(screen.getByText('Next'));

      expect(screen.getByRole('img')).toHaveAttribute('src', 'https://example.com/image2.jpg');
      expect(screen.getByText('2 / 2')).toBeInTheDocument();
    });

    it('should navigate to previous image', async () => {
      const user = userEvent.setup();
      render(
        <ImageGallery
          images={[
            { url: 'https://example.com/image1.jpg', alt: 'Image 1' },
            { url: 'https://example.com/image2.jpg', alt: 'Image 2' },
          ]}
        />
      );

      await user.click(screen.getByText('Next'));
      expect(screen.getByText('2 / 2')).toBeInTheDocument();

      await user.click(screen.getByText('Prev'));
      expect(screen.getByText('1 / 2')).toBeInTheDocument();
    });

    it('should wrap around when navigating past the end', async () => {
      const user = userEvent.setup();
      render(
        <ImageGallery
          images={[
            { url: 'https://example.com/image1.jpg', alt: 'Image 1' },
            { url: 'https://example.com/image2.jpg', alt: 'Image 2' },
          ]}
        />
      );

      await user.click(screen.getByText('Next'));
      await user.click(screen.getByText('Next'));

      expect(screen.getByText('1 / 2')).toBeInTheDocument();
    });

    it('should wrap around when navigating before the start', async () => {
      const user = userEvent.setup();
      render(
        <ImageGallery
          images={[
            { url: 'https://example.com/image1.jpg', alt: 'Image 1' },
            { url: 'https://example.com/image2.jpg', alt: 'Image 2' },
          ]}
        />
      );

      await user.click(screen.getByText('Prev'));

      expect(screen.getByText('2 / 2')).toBeInTheDocument();
    });

    it('should have proper aria-label', () => {
      render(
        <ImageGallery
          images={[{ url: 'https://example.com/image.jpg', alt: 'Test' }]}
          title="My Gallery"
        />
      );

      expect(screen.getByRole('region')).toHaveAttribute('aria-label', 'My Gallery');
    });

    it('should use default aria-label when title is not provided', () => {
      render(
        <ImageGallery
          images={[{ url: 'https://example.com/image.jpg', alt: 'Test' }]}
        />
      );

      expect(screen.getByRole('region')).toHaveAttribute('aria-label', 'Image gallery');
    });
  });
});

