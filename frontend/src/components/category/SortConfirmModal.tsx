import { ModalDialog } from '../common/ModalDialog';
interface SortConfirmModalProps {
  onConfirm: (scope: 'level' | 'all') => void;
  onCancel: () => void;
}

function SortConfirmModal({ onConfirm, onCancel }: SortConfirmModalProps) {
  return (
    <ModalDialog label="Sort Categories Alphabetically" onClose={onCancel}>
      <div className="modal" style={{ maxWidth: '420px' }}>
        <div className="modal__header">
          <h2 className="modal__title">Sort Categories Alphabetically</h2>
        </div>
        <div className="modal__body">
          <p className="modal__info">
            This will overwrite any custom ordering you have set.
          </p>
          <div className="modal__actions">
            <button
              type="button"
              className="modal__button modal__button--primary"
              onClick={() => onConfirm('level')}
              aria-label="This level only"
            >
              This Level Only
            </button>
            <button
              type="button"
              className="modal__button modal__button--primary"
              onClick={() => onConfirm('all')}
              aria-label="All levels"
            >
              All Levels
            </button>
          </div>
        </div>
        <div className="modal__footer">
          <button
            type="button"
            className="modal__button modal__button--secondary"
            onClick={onCancel}
            aria-label="Cancel"
          >
            Cancel
          </button>
        </div>
      </div>
    </ModalDialog>
  );
}

export default SortConfirmModal;
