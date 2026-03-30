interface BulkActionBarProps {
  selectedCount: number;
  onPublish: () => void;
  onUnpublish: () => void;
  onCancel: () => void;
}

function BulkActionBar({ selectedCount, onPublish, onUnpublish, onCancel }: BulkActionBarProps) {
  if (selectedCount === 0) return null;

  return (
    <div className="bulk-action-bar">
      <span className="bulk-action-bar__count">{selectedCount}</span>
      <span className="bulk-action-bar__text">items selected</span>
      <button
        className="bulk-action-bar__button bulk-action-bar__button--publish"
        onClick={onPublish}
        type="button"
      >
        Publish Selected
      </button>
      <button
        className="bulk-action-bar__button bulk-action-bar__button--unpublish"
        onClick={onUnpublish}
        type="button"
      >
        Make Private
      </button>
      <button
        className="bulk-action-bar__button bulk-action-bar__button--cancel"
        onClick={onCancel}
        type="button"
      >
        Cancel
      </button>
    </div>
  );
}

export { BulkActionBar };
export type { BulkActionBarProps };
