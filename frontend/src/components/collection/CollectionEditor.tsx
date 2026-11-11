import { useId, useState } from 'react';
import type { Collection } from '../../utils/types';
import { usePublish } from '../../contexts/usePublish';
import { useCollectionDraft, type SaveCollection } from '../../data/collections/useCollectionDraft';
import { useEditorStatus, type EditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import CollectionTemplateEditor from './CollectionTemplateEditor';
import { ContentState } from '../common/ContentState';
import '../../styles/components/CollectionEditor.css';

interface CollectionEditorProps {
  collection: Collection;
  saveCollection: SaveCollection;
  onClose: () => void;
  onStatusChange: EditorStatusListener;
}

export function CollectionEditor({ collection, saveCollection, onClose, onStatusChange }: CollectionEditorProps) {
  const editor = useCollectionDraft(collection, saveCollection, onClose);
  const { requestPublish, requestUnpublish } = usePublish();
  const [templatesOpen, setTemplatesOpen] = useState(false);
  const [templatesStatus, setTemplatesStatus] = useState<EditorStatus>({ dirty: false, pending: false });
  useEditorStatus(editor.dirty || templatesStatus.dirty, editor.pending || templatesStatus.pending, onStatusChange);
  const id = useId();

  function cancel() {
    if (!editor.dirty || window.confirm('You have unsaved changes. Discard them?')) onClose();
  }

  if (templatesOpen) return <CollectionTemplateEditor collection={collection} onClose={() => setTemplatesOpen(false)} onStatusChange={setTemplatesStatus} />;

  return <form className="collection-editor" aria-label="Edit collection" onSubmit={event => { event.preventDefault(); void editor.save(); }}>
    <h3 className="collection-editor__title">Edit Collection</h3>
    {editor.error && <ContentState kind="error" title="Unable to save collection">{editor.error}</ContentState>}
    <fieldset className="collection-editor__fields" disabled={editor.pending} aria-busy={editor.pending}>
      <div className="collection-editor__field">
        <label htmlFor={`${id}-name`}>Name <span aria-hidden="true">*</span></label>
        <input id={`${id}-name`} type="text" aria-required="true" value={editor.draft.name} autoFocus
          placeholder="My Collection" onChange={event => editor.setDraft(previous => ({ ...previous, name: event.target.value }))} />
      </div>
      <div className="collection-editor__field">
        <label htmlFor={`${id}-description`}>Description</label>
        <textarea id={`${id}-description`} value={editor.draft.description} rows={3} placeholder="A brief description of this collection"
          onChange={event => editor.setDraft(previous => ({ ...previous, description: event.target.value }))} />
      </div>
      <div className="collection-editor__field">
        <label htmlFor={`${id}-image`}>Hero Image URL</label>
        <input id={`${id}-image`} type="url" value={editor.draft.heroImageUrl} placeholder="https://example.com/image.jpg"
          onChange={event => editor.setDraft(previous => ({ ...previous, heroImageUrl: event.target.value }))} />
      </div>
      <div className="collection-editor__field">
        <h4>Item Templates</h4>
        <p>Configure which templates are available when creating items in this collection. Your collection draft is kept while you manage templates.</p>
        <button type="button" onClick={() => setTemplatesOpen(true)}>Manage Templates</button>
      </div>
      <div className="collection-editor__field">
        <h4>Visibility</h4>
        {collection.effectiveIsPublic ? <>
          <p>This collection is currently visible in your public gallery.</p>
          <button type="button" className="collection-editor__danger" onClick={() => requestUnpublish([{ type: 'collection', id: collection.collectionId }])}>Unpublish Collection</button>
        </> : <>
          <p>This collection is private. Publish it to make it visible in your public gallery.</p>
          <button type="button" onClick={() => requestPublish([{ type: 'collection', id: collection.collectionId }])}>Publish Collection</button>
        </>}
      </div>
      <div className="collection-editor__actions">
        <button type="submit" className="collection-editor__primary">{editor.pending ? 'Saving...' : 'Save Changes'}</button>
        <button type="button" onClick={cancel}>Cancel</button>
      </div>
    </fieldset>
  </form>;
}
