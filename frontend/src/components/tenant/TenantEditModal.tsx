import { useState, useEffect, useRef } from 'react';
import type { TenantMembership } from '../../utils/types';
import { tenantsApi } from '../../api';

interface TenantEditModalProps {
  tenant: TenantMembership | null;
  isOpen: boolean;
  onClose: () => void;
  onSaved?: () => void;
}

function TenantEditModal({ tenant, isOpen, onClose, onSaved }: TenantEditModalProps) {
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const dialogRef = useRef<HTMLDialogElement>(null);

  // Control dialog open/close
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    if (isOpen) {
      dialog.showModal();
    } else {
      dialog.close();
    }
  }, [isOpen]);

  // Handle native dialog close (e.g., Escape key)
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    const handleClose = () => {
      onClose();
    };

    dialog.addEventListener('close', handleClose);
    return () => dialog.removeEventListener('close', handleClose);
  }, [onClose]);

  // Reset form when modal opens or tenant changes
  useEffect(() => {
    if (isOpen && tenant) {
      setName(tenant.tenantName);
      setError(null);
    }
  }, [isOpen, tenant]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const trimmedName = name.trim();
    if (!trimmedName) {
      setError('Tenant name is required');
      return;
    }

    if (!tenant) return;

    setIsSubmitting(true);
    setError(null);

    try {
      await tenantsApi.update(tenant.tenantId, { name: trimmedName });
      onSaved?.();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleBackdropClick = (e: React.MouseEvent<HTMLDialogElement>) => {
    if (e.target === dialogRef.current) {
      onClose();
    }
  };

  return (
    <dialog ref={dialogRef} className="modal-dialog" onClick={handleBackdropClick}>
      <div className="modal">
        <div className="modal__header">
          <h2 className="modal__title">Edit Tenant</h2>
          <button
            type="button"
            className="modal__close"
            onClick={onClose}
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <form className="modal__body" onSubmit={handleSubmit}>
          {error && (
            <div className="modal__error" role="alert">
              {error}
            </div>
          )}

          <div className="modal__field">
            <label htmlFor="tenant-name" className="modal__label">
              Tenant Name <span className="modal__required">*</span>
            </label>
            <input
              id="tenant-name"
              type="text"
              className="modal__input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Tenant name"
              required
              autoFocus
              maxLength={200}
            />
          </div>

          <div className="modal__actions">
            <button
              type="submit"
              className="detail__btn detail__btn--primary"
              disabled={isSubmitting || !name.trim()}
            >
              {isSubmitting ? 'Saving...' : 'Save'}
            </button>
            <button
              type="button"
              className="detail__btn detail__btn--secondary"
              onClick={onClose}
              disabled={isSubmitting}
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </dialog>
  );
}

export default TenantEditModal;
