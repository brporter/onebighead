import { useId, useState } from 'react';
import { useCategoriesData } from '../../contexts/useData';
import { usePublish } from '../../contexts/usePublish';
import { useCategoryManager } from '../../data/categories/useCategoryManager';
import { ModalDialog } from '../common/ModalDialog';
import { ContentState } from '../common/ContentState';
import CategoryManagerTree from './CategoryManagerTree';
import CategoryManagerForm from './CategoryManagerForm';
import QuickCreatePopover from './QuickCreatePopover';
import './CategoryManagerModal.css';

interface CategoryManagerModalProps { collectionId: number; isOpen: boolean; onClose: () => void }

export default function CategoryManagerModal({ collectionId, isOpen, onClose }: CategoryManagerModalProps) {
  return isOpen ? <CategoryManagerSession key={collectionId} collectionId={collectionId} onClose={onClose} /> : null;
}

function CategoryManagerSession({ collectionId, onClose }: Omit<CategoryManagerModalProps, 'isOpen'>) {
  const manager = useCategoryManager(collectionId, useCategoriesData(), onClose);
  const { requestPublish, requestUnpublish } = usePublish();
  const formId = useId();
  const [deleting, setDeleting] = useState(false);
  const form = manager.editor.type === 'form' ? manager.editor : null;
  const selected = manager.categories.find(category => category.categoryId === form?.category?.categoryId) ?? form?.category;
  const close = () => manager.leave('close');
  const back = () => manager.leave('tree');
  const confirmDelete = () => {
    setDeleting(false);
    void manager.execute({ type: 'delete', categoryId: selected!.categoryId });
  };

  return <ModalDialog onClose={close} className="modal-dialog--wide" label="Category Manager">
    <div className="modal modal--wide categoryManager">
      <div className="modal__header">
        <h2 className="modal__title">Category Manager</h2>
        <button type="button" className="modal__close" onClick={close} disabled={manager.pending} aria-label="Close">&times;</button>
      </div>
      <div key={manager.editor.type} className="categoryManager__body" aria-busy={manager.pending}>
        {manager.error && <div className="modal__error" role="alert">
          <p>{manager.saved ? 'Your change was saved, but the remaining steps could not finish.' : 'Unable to save your changes.'} {manager.error}</p>
          <button type="button" className="modal__button" disabled={manager.pending} onClick={() => void manager.retry()}>
            {manager.saved ? 'Finish saving' : 'Try again'}
          </button>
        </div>}
        {manager.pending && <p role="status">Saving category changes…</p>}
        {manager.resource.loading ? <ContentState kind="loading" title="Loading categories…" /> :
          manager.resource.error ? <ContentState kind="error" title="Unable to load categories"
            action={<button type="button" onClick={manager.resource.retry}>Try again</button>}>{manager.resource.error}</ContentState> :
          manager.editor.type === 'tree' ? <CategoryManagerTree categories={manager.categories} disabled={manager.locked}
            onEditCategory={id => manager.openForm(manager.categories.find(category => category.categoryId === id)!)}
            onAdd={manager.openQuick} onReorder={updates => void manager.execute({ type: 'reorder', updates })}
            onReparent={(categoryId, parentId, insertAtCategoryId, insertAfter) => void manager.execute({ type: 'reparent', categoryId, parentId, insertAtCategoryId, insertAfter })} /> :
          manager.editor.type === 'quick' ? <>
            <h3>Add category</h3><p className="categoryManager__hint">Start with a name, or add details and choose a parent category.</p>
            <QuickCreatePopover isVisible disabled={manager.locked} onSave={name => void manager.execute({ type: 'quick-create', name })}
              onMoreDetails={name => manager.openForm(null, name)} onCancel={back} onHasChanges={manager.setDirty} />
          </> : <CategoryManagerForm category={selected ?? null} categories={manager.categories} collectionId={collectionId}
            isNew={!form!.category} initialName={form!.initialName} onSave={draft => void manager.execute({ type: 'save', categoryId: form!.category?.categoryId ?? null, draft })}
            onBack={back} onHasChanges={manager.setDirty} formId={formId} disabled={manager.locked}
            onPublish={category => requestPublish([{ type: 'category', id: category.categoryId }])}
            onUnpublish={category => requestUnpublish([{ type: 'category', id: category.categoryId }])} />}
      </div>
      {manager.editor.type !== 'quick' && <div className="categoryManager__footer">
        {form ? <>
          {selected && !selected.isSystem && <button type="button" className="modal__button modal__button--danger" disabled={manager.locked} onClick={() => setDeleting(true)}>Delete</button>}
          <div className="categoryManager__footer-right">
            <button type="button" className="modal__button modal__button--secondary" disabled={manager.locked} onClick={back}>Cancel</button>
            <button type="submit" form={formId} className="modal__button modal__button--primary" disabled={manager.locked || selected?.isSystem}>
              {selected ? 'Save Changes' : 'Create'}
            </button>
          </div>
        </> : <button type="button" className="modal__button modal__button--secondary categoryManager__close" disabled={manager.pending} onClick={close}>Close</button>}
      </div>}
    </div>
    {deleting && <ModalDialog label="Delete Category" onClose={() => setDeleting(false)}>
      <div className="modal">
        <div className="modal__header"><h2 className="modal__title">Delete Category</h2></div>
        <div className="modal__body"><p>Delete “{selected!.name}”? Items will move to “Unassigned Items”. Child categories will move to this category’s parent.</p></div>
        <div className="modal__footer">
          <button type="button" className="modal__button" onClick={() => setDeleting(false)}>Cancel</button>
          <button type="button" className="modal__button modal__button--danger" onClick={confirmDelete}>Delete</button>
        </div>
      </div>
    </ModalDialog>}
    {manager.destination && <ModalDialog label={manager.saved ? 'Leave saved changes' : 'Discard Changes'} onClose={manager.cancelLeave}>
      <div className="modal">
        <div className="modal__header"><h2 className="modal__title">{manager.saved ? 'Leave saved changes?' : 'Discard Changes'}</h2></div>
        <div className="modal__body"><p>{manager.saved ? 'Some changes are already saved. Leaving will not undo them, and the category order may still need updating.' : 'You have unsaved changes. Are you sure you want to discard them?'}</p></div>
        <div className="modal__footer">
          <button type="button" className="modal__button" onClick={manager.cancelLeave}>Keep Editing</button>
          <button type="button" className="modal__button modal__button--danger" onClick={manager.confirmLeave}>{manager.saved ? 'Leave' : 'Discard'}</button>
        </div>
      </div>
    </ModalDialog>}
  </ModalDialog>;
}
