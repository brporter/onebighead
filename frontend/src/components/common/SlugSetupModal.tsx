import { useState } from 'react';
import { isValidSlug } from '../../utils/slugUtils';

interface SlugSetupModalProps {
  existingSlug?: string | null;
  onConfirm: (slug: string) => void;
  onCancel: () => void;
}

function SlugSetupModal({ existingSlug, onConfirm, onCancel }: SlugSetupModalProps) {
  const [slug, setSlug] = useState(existingSlug ?? '');
  const hasExistingSlug = !!existingSlug;
  const slugValid = isValidSlug(slug);

  const handleSubmit = () => {
    if (slugValid) {
      onConfirm(slug);
    }
  };

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal slug-setup-modal" onClick={e => e.stopPropagation()}>
        <div className="modal__header">
          <h2 className="modal__title">Set Up Your Public Gallery</h2>
          <button className="modal__close" onClick={onCancel} type="button">
            &times;
          </button>
        </div>

        <div className="modal__body">
          {hasExistingSlug ? (
            <p className="slug-setup-modal__info">Your gallery URL is already set.</p>
          ) : (
            <p className="slug-setup-modal__info">
              Choose a URL for your public gallery. Use lowercase letters, numbers, and hyphens (3-50 characters).
            </p>
          )}

          <div className="slug-setup-modal__input-group">
            <label className="slug-setup-modal__label" htmlFor="slug-input">Gallery URL</label>
            <input
              id="slug-input"
              type="text"
              className="slug-setup-modal__input"
              value={slug}
              onChange={e => setSlug(e.target.value)}
              placeholder="my-collection"
              maxLength={50}
            />
          </div>

          <p className="slug-setup-modal__preview">
            /public/{slug}
          </p>
        </div>

        <div className="modal__footer">
          <button
            className="modal__button modal__button--secondary"
            onClick={onCancel}
            type="button"
          >
            Cancel
          </button>
          <button
            className="modal__button modal__button--primary"
            onClick={handleSubmit}
            disabled={!slugValid}
            type="button"
          >
            {hasExistingSlug ? 'Continue & Publish' : 'Create Gallery & Publish'}
          </button>
        </div>
      </div>
    </div>
  );
}

export { SlugSetupModal };
export type { SlugSetupModalProps };
