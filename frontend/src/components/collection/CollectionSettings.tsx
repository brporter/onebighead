import { useEffect, useState } from 'react';
import { useCollectionsData } from '../../contexts/useData';
import type { Collection } from '../../utils/types';
import { useAsyncAction } from '../../utils/useAsyncAction';
import { useEditorStatus, type EditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import { ContentState } from '../common/ContentState';
import { CategoryManagerModal } from '../category';
import CollectionTemplateEditor from './CollectionTemplateEditor';
import CollectionSetupWizard from './CollectionSetupWizard';
import { CollectionEditor } from './CollectionEditor';
import '../../styles/components/CollectionSettings.css';

type Session = { kind: 'create' } | { kind: 'edit' | 'templates'; id: number } | null;

interface CollectionSettingsProps { isAdmin: boolean; onStatusChange: EditorStatusListener }

export function CollectionSettings({ isAdmin, onStatusChange }: CollectionSettingsProps) {
  const { collections, collectionsLoading, collectionsError, loadCollections, updateCollection, deleteCollection } = useCollectionsData();
  const [session, setSession] = useState<Session>(null);
  const [categoryId, setCategoryId] = useState<number | null>(null);
  const [editorStatus, setEditorStatus] = useState<EditorStatus>({ dirty: false, pending: false });
  const removal = useAsyncAction();
  useEditorStatus(editorStatus.dirty, editorStatus.pending || removal.pending, onStatusChange);
  useEffect(() => { void loadCollections(); }, [loadCollections]);

  function close() { setSession(null); setEditorStatus({ dirty: false, pending: false }); }

  function remove(collection: Collection) {
    if (!window.confirm(`Delete "${collection.name}"? All items and categories within it will be permanently deleted.`)) return;
    // The domain operation updates the shared collection cache after success.
    void removal.run(() => deleteCollection(collection.collectionId), 'Failed to delete collection');
  }

  if (session?.kind === 'create') return <CollectionSetupWizard isModal onComplete={close} onCancel={close} onStatusChange={setEditorStatus} />;
  if (session) {
    const collection = collections.find(item => item.collectionId === session.id);
    if (!collection) return <ContentState kind="empty" title="This collection is no longer available"
      action={<button type="button" onClick={close}>Back to collections</button>} />;
    return session.kind === 'edit' ? <CollectionEditor key={collection.collectionId} collection={collection}
      saveCollection={updateCollection} onClose={close} onStatusChange={setEditorStatus} /> :
      <CollectionTemplateEditor collection={collection} onClose={close} onStatusChange={setEditorStatus} />;
  }

  return <section className="settings-section collection-settings" aria-labelledby="collection-settings-title">
    <div className="settings-section__header">
      <div>
        <h2 id="collection-settings-title" className="settings-section__title">Collections</h2>
        <p className="settings-section__description">Manage your collections. Each collection can have categories and items.</p>
      </div>
      {isAdmin && <button type="button" className="collection-settings__create" disabled={removal.pending} onClick={() => setSession({ kind: 'create' })}>+ New Collection</button>}
    </div>
    {removal.error && <ContentState kind="error" title="Unable to delete collection">{removal.error}</ContentState>}
    {removal.pending && <ContentState kind="loading" title="Deleting collection…" />}
    {collectionsLoading ? <ContentState kind="loading" title="Loading collections…" /> : collectionsError ?
      <ContentState kind="error" title="Unable to load collections" action={<button type="button" onClick={() => void loadCollections()}>Try again</button>}>{collectionsError}</ContentState> :
      collections.length === 0 ? <ContentState kind="empty" title="No collections yet">Create a collection to start organizing your items.</ContentState> :
        <div className="settings-collection-grid">
          {collections.map(collection => <article className="settings-collection-card" key={collection.collectionId} aria-label={collection.name}>
            <div className="settings-collection-card__content">
              <h3 className="settings-collection-card__name">{collection.name}</h3>
              {collection.description && <p className="settings-collection-card__description">{collection.description}</p>}
              <div className="settings-collection-card__meta">
                <span className={`settings-collection-card__visibility ${collection.effectiveIsPublic ? 'settings-collection-card__visibility--public' : ''}`}>
                  {collection.effectiveIsPublic ? '🌐 Public' : '🔒 Private'}
                </span>
              </div>
            </div>
            <div className="settings-collection-card__actions">
              <button type="button" className="settings-collection-card__button" disabled={removal.pending} onClick={() => setCategoryId(collection.collectionId)}>Categories</button>
              <button type="button" className="settings-collection-card__button" disabled={removal.pending} onClick={() => setSession({ kind: 'templates', id: collection.collectionId })}>Templates</button>
              <button type="button" className="settings-collection-card__button" disabled={removal.pending} onClick={() => setSession({ kind: 'edit', id: collection.collectionId })}>Edit</button>
              {isAdmin && collections.length > 1 && <button type="button" className="settings-collection-card__button settings-collection-card__button--danger"
                disabled={removal.pending} onClick={() => remove(collection)}>Delete</button>}
            </div>
          </article>)}
        </div>}
    {categoryId !== null && <CategoryManagerModal collectionId={categoryId} isOpen onClose={() => setCategoryId(null)} />}
  </section>;
}
