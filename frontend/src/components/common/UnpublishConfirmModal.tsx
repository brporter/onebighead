interface UnpublishConfirmModalProps {
  entityType: 'category' | 'collection';
  entityName: string;
  affectedPublicItems: number;
  affectedPublicCategories?: number;
  onConfirm: () => void;
  onCancel: () => void;
}

function UnpublishConfirmModal({
  entityType,
  entityName,
  affectedPublicItems,
  affectedPublicCategories,
  onConfirm,
  onCancel,
}: UnpublishConfirmModalProps) {
  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal unpublish-confirm-modal" onClick={e => e.stopPropagation()}>
        <div className="modal__header">
          <h2 className="modal__title">Make &apos;{entityName}&apos; Private?</h2>
          <button className="modal__close" onClick={onCancel} type="button">
            &times;
          </button>
        </div>

        <div className="modal__body">
          <p className="unpublish-confirm-modal__warning">
            This {entityType} has {affectedPublicItems} {affectedPublicItems === 1 ? 'item' : 'items'} currently visible in your public gallery.
            {entityType === 'collection' && affectedPublicCategories != null && affectedPublicCategories > 0 && (
              <> It also has {affectedPublicCategories} {affectedPublicCategories === 1 ? 'category' : 'categories'} that will be affected.</>
            )}
            {' '}They will be hidden, but if you make this {entityType} public again, they&apos;ll reappear. Continue?
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
            className="modal__button modal__button--danger"
            onClick={onConfirm}
            type="button"
          >
            Make Private
          </button>
        </div>
      </div>
    </div>
  );
}

export { UnpublishConfirmModal };
export type { UnpublishConfirmModalProps };
