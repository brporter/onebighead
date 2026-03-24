interface PublishConfirmModalProps {
  entityType: 'category' | 'collection';
  entityName: string;
  itemCount: number;
  categoryCount?: number;
  onConfirm: (includeChildren: boolean) => void;
  onCancel: () => void;
}

function PublishConfirmModal({
  entityType,
  entityName,
  itemCount,
  categoryCount,
  onConfirm,
  onCancel,
}: PublishConfirmModalProps) {
  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal publish-confirm-modal" onClick={e => e.stopPropagation()}>
        <div className="modal__header">
          <h2 className="modal__title">Publish {entityType} &apos;{entityName}&apos;?</h2>
          <button className="modal__close" onClick={onCancel} type="button">
            &times;
          </button>
        </div>

        <div className="modal__body">
          <p className="publish-confirm-modal__info">
            This {entityType} contains {itemCount} {itemCount === 1 ? 'item' : 'items'}
            {entityType === 'collection' && categoryCount != null && categoryCount > 0 && (
              <> and {categoryCount} {categoryCount === 1 ? 'category' : 'categories'}</>
            )}
            .
          </p>

          <div className="publish-confirm-modal__options">
            <button
              className="modal__button modal__button--primary"
              onClick={() => onConfirm(true)}
              type="button"
            >
              Publish {entityType} and all {itemCount} items
            </button>
            <button
              className="modal__button modal__button--secondary"
              onClick={() => onConfirm(false)}
              type="button"
            >
              Publish {entityType} only
            </button>
          </div>
        </div>

        <div className="modal__footer">
          <button
            className="modal__button modal__button--secondary"
            onClick={onCancel}
            type="button"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

export { PublishConfirmModal };
export type { PublishConfirmModalProps };
