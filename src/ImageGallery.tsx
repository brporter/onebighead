import { useId, useMemo, useState } from 'react';
import type { ItemImage } from './types';

interface ImageGalleryProps {
  images?: (string | ItemImage)[];
  title?: string;
}

interface NormalizedImage {
  url: string;
  alt: string;
}

function normalizeImages(images: (string | ItemImage)[] | undefined): NormalizedImage[] {
  return (images ?? [])
    .filter(Boolean)
    .map((img): NormalizedImage => {
      if (typeof img === 'string') return { url: img, alt: '' };
      return { url: img.url, alt: img.alt ?? '' };
    })
    .filter((img) => img.url.trim().length > 0);
}

function ImageGallery({ images, title }: ImageGalleryProps) {
  const galleryId = useId();
  const normalized = useMemo(() => normalizeImages(images), [images]);
  const [index, setIndex] = useState(0);

  const count = normalized.length;
  if (!count) return null;

  const safeIndex = index % count;
  const current = normalized[safeIndex];
  const hasMultiple = count > 1;

  function goPrev() {
    setIndex((i) => (i - 1 + count) % count);
  }

  function goNext() {
    setIndex((i) => (i + 1) % count);
  }

  return (
    <section className="gallery" aria-label={title || 'Image gallery'}>
      <div className="gallery__viewport">
        <img
          className="gallery__image"
          src={current.url}
          alt={current.alt || title || ''}
          loading="lazy"
        />
      </div>

      {hasMultiple ? (
        <div className="gallery__controls">
          <button
            type="button"
            className="gallery__button"
            onClick={goPrev}
            aria-controls={galleryId}
          >
            Prev
          </button>
          <div id={galleryId} className="gallery__status" aria-live="polite">
            {safeIndex + 1} / {count}
          </div>
          <button
            type="button"
            className="gallery__button"
            onClick={goNext}
            aria-controls={galleryId}
          >
            Next
          </button>
        </div>
      ) : null}
    </section>
  );
}

export default ImageGallery;

