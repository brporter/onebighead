import { useId, useMemo, useState } from 'react'
import PropTypes from 'prop-types'

function normalizeImages(images) {
  // Start with the provided images array; if it's null/undefined, fall back to an empty array.
  return (images ?? [])
    // Remove any null/undefined/false entries from the array.
    .filter(Boolean)
    // Convert each entry into a normalized object shape: { url, alt }.
    .map((img) => {
      // If the entry is a string, treat it as the image URL and provide an empty alt.
      if (typeof img === 'string') return { url: img, alt: '' }
      // Otherwise assume it's an object and pluck url + alt (default alt to empty string).
      return { url: img.url, alt: img.alt ?? '' }
    })
    // Keep only entries whose url is a non-empty (after trimming) string.
    .filter((img) => typeof img.url === 'string' && img.url.trim().length)
}

function ImageGallery({ images, title }) {
  const galleryId = useId()
  const normalized = useMemo(() => normalizeImages(images), [images])
  const [index, setIndex] = useState(0)

  const count = normalized.length
  if (!count) return null

  const safeIndex = index % count
  const current = normalized[safeIndex]
  const hasMultiple = count > 1

  function goPrev() {
    setIndex((i) => (i - 1 + count) % count)
  }

  function goNext() {
    setIndex((i) => (i + 1) % count)
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
  )
}

ImageGallery.propTypes = {
  images: PropTypes.arrayOf(
    PropTypes.oneOfType([
      PropTypes.string,
      PropTypes.shape({
        url: PropTypes.string.isRequired,
        alt: PropTypes.string,
      }),
    ]),
  ),
  title: PropTypes.string,
}

ImageGallery.defaultProps = {
  images: [],
  title: '',
}

export default ImageGallery
