import { useCallback, useState } from 'react';
import { useEditorStatus, type EditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import PropertyEditor from './PropertyEditor';
import ImageEditor from '../common/ImageEditor';
import CategorySelector from '../category/CategorySelector';
import type { Item, Category, ItemProperty, Collection } from '../../utils/types';
import { UserFlag } from '../../utils/types';
import { createEmptyItem } from '../../utils/itemUtils';
import { createItemDraft, itemFromDraft, sameItemDraft, type ItemDraft } from '../../data/items/itemDraft';
import { useAsyncAction } from '../../utils/useAsyncAction';
import { ContentState } from '../common/ContentState';
import '../../styles/components/ItemEditor.css';

interface ItemEditorProps {
  item: Item | null;
  categories: Category[];
  collection: Collection | null;
  onSave: (item: Item) => void | Promise<void>;
  onCancel: () => void;
  onDelete?: ((id: number) => void | Promise<void>) | null;
  initialProperties?: ItemProperty[];
  onStatusChange?: EditorStatusListener;
}

function ItemEditor(props: ItemEditorProps) {
  if (!props.item && !props.collection) return <ContentState kind="error" title="Choose a collection before adding an item" />;
  return <ItemEditorForm {...props} />;
}

function ItemEditorForm({
  item,
  categories,
  collection,
  onSave,
  onCancel,
  onDelete,
  initialProperties,
  onStatusChange,
}: ItemEditorProps) {
  const [original] = useState<ItemDraft>(() => createItemDraft(item ?? {
      ...createEmptyItem(null, collection!.collectionId, collection!.workspaceId),
      properties: initialProperties ?? [],
  }));
  const [formData, setFormData] = useState(original);

  const isNew = formData.id === null;
  const action = useAsyncAction();
  const [imagesPending, setImagesPending] = useState(false);
  const reportImages = useCallback((status: EditorStatus) => setImagesPending(status.pending), []);
  const pending = action.pending || imagesPending;
  const dirty = !sameItemDraft(original, formData);
  useEditorStatus(dirty, pending, onStatusChange);

  function handleCancel() {
    if (pending || (dirty && !window.confirm('You have unsaved changes. Discard them?'))) return;
    onCancel();
  }

  function handleFieldChange<K extends keyof ItemDraft>(field: K, value: ItemDraft[K]) {
    setFormData((prev) => ({ ...prev, [field]: value }));
  }

  function handleDelete() {
    if (window.confirm(`Are you sure you want to delete "${item!.name}"?`)) {
      void action.run(() => onDelete!(formData.id!), 'Unable to delete item');
    }
  }

  return (
    <section className="detail detail--editing">
      <form className="detail__form" aria-busy={pending} onSubmit={(e) => {
        e.preventDefault();
        if (!pending && formData.name.trim()) void action.run(() => onSave(itemFromDraft(formData)), 'Unable to save item');
      }}>
        {action.error && <ContentState kind="error" title="Unable to complete this action">{action.error}</ContentState>}
        <fieldset className="item-editor__fields" disabled={pending} inert={pending} aria-label="Item details">
        <div className="detail__header">
          <h2 className="detail__title">
            {isNew ? 'Add New Item' : `Edit: ${item!.name}`}
          </h2>
        </div>

        <div className="detail__field">
          <label htmlFor="item-name" className="detail__label">Name</label>
          <input
            id="item-name"
            type="text"
            className="detail__input"
            value={formData.name}
            onChange={(e) => handleFieldChange('name', e.target.value)}
            placeholder="Item name"
            required
            autoComplete="off"
          />
        </div>

        <div className="detail__field">
          <label htmlFor="item-summary" className="detail__label">Summary</label>
          <input
            id="item-summary"
            type="text"
            className="detail__input"
            value={formData.summary}
            onChange={(e) => handleFieldChange('summary', e.target.value)}
            placeholder="Brief summary"
          />
        </div>

        <div className="detail__field">
          <label htmlFor="item-description" className="detail__label">Description</label>
          <textarea
            id="item-description"
            className="detail__textarea"
            value={formData.description}
            onChange={(e) => handleFieldChange('description', e.target.value)}
            placeholder="Full description"
            rows={4}
          />
        </div>

        <CategorySelector
          categories={categories}
          selectedCategoryId={formData.categoryId}
          onChange={(categoryId) => handleFieldChange('categoryId', categoryId)}
        />

        <PropertyEditor
          properties={formData.properties}
          onChange={(props) => handleFieldChange('properties', props)}
        />

        <ImageEditor
          images={formData.images}
          onChange={update => setFormData(current => ({ ...current, images: update(current.images) }))}
          onStatusChange={reportImages}
        />

        <fieldset className="detail__fieldset">
          <legend className="detail__legend">My Relationship to This Item</legend>
          <div className="detail__radioGroup">
            <label className="detail__radioLabel">
              <input
                type="radio"
                name="userFlag"
                className="detail__radioInput"
                checked={formData.userFlag === UserFlag.Have}
                onChange={() => handleFieldChange('userFlag', UserFlag.Have)}
              />
              <span className="detail__radioText">I Have This</span>
            </label>
            <label className="detail__radioLabel">
              <input
                type="radio"
                name="userFlag"
                className="detail__radioInput"
                checked={formData.userFlag === UserFlag.Want}
                onChange={() => handleFieldChange('userFlag', UserFlag.Want)}
              />
              <span className="detail__radioText">I Want This</span>
            </label>
            <label className="detail__radioLabel">
              <input
                type="radio"
                name="userFlag"
                className="detail__radioInput"
                checked={formData.userFlag === UserFlag.TradeOrSell}
                onChange={() => handleFieldChange('userFlag', UserFlag.TradeOrSell)}
              />
              <span className="detail__radioText">For Trade/Sale</span>
            </label>
          </div>
        </fieldset>

        <div className="detail__actions">
          <button
            type="submit"
            className="detail__btn detail__btn--primary"
            disabled={!formData.name.trim()}
          >
            {isNew ? 'Create Item' : 'Save Changes'}
          </button>
          <button
            type="button"
            className="detail__btn detail__btn--secondary"
            onClick={handleCancel}
          >
            Cancel
          </button>
          {!isNew && onDelete && (
            <button
              type="button"
              className="detail__btn detail__btn--danger"
              onClick={handleDelete}
            >
              Delete
            </button>
          )}
        </div>
        </fieldset>
      </form>
    </section>
  );
}

export default ItemEditor;

