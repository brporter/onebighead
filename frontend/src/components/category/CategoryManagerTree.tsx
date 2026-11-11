import { useId, useMemo, type ReactNode } from 'react';
import { DndContext, DragOverlay, KeyboardSensor, MeasuringStrategy, PointerSensor, useDroppable, useSensor, useSensors } from '@dnd-kit/core';
import { SortableContext, sortableKeyboardCoordinates, useSortable } from '@dnd-kit/sortable';
import type { Category } from '../../utils/types';
import { getAccentColor } from '../../utils/accentColors';
import { categoryCollisionDetection, useCategoryTreeDrag } from '../../data/categories/useCategoryTreeDrag';
import type { DropIntent } from '../../data/categories/categoryDrop';
import { DragHandle } from '../common/DragHandle';
import '../../styles/components/CategoryManagerTree.css';
import { CategoryHierarchy, type CategoryRow } from '../../data/categories/CategoryHierarchy';

export interface CategoryManagerTreeProps {
  categories: Category[];
  onEditCategory: (categoryId: number) => void;
  onAdd: () => void;
  onReorder: (updates: { categoryId: number; sortOrder: number }[]) => void;
  onReparent: (categoryId: number, newParentId: number | null, insertAtCategoryId?: number, insertAfter?: boolean) => void;
  toolbarSlot?: ReactNode;
  disabled?: boolean;
}

function RootDropZone({ disabled }: { disabled: boolean }) {
  const { setNodeRef, isOver } = useDroppable({ id: 'root-drop-zone', disabled });
  return <div ref={setNodeRef} className={`catTree__rootDropZone${isOver ? ' catTree__rootDropZone--over' : ''}`}>
    Move here to make root level
  </div>;
}

function SortableRow({ row, onEdit, intent, disabled }: {
  row: CategoryRow; onEdit: (id: number) => void; intent: DropIntent | null; disabled: boolean;
}) {
  const { attributes, listeners, setNodeRef, isDragging } = useSortable({ id: String(row.category.categoryId), disabled, animateLayoutChanges: () => false });
  const modifier = intent === 'reparent' ? 'dropTarget' : intent === 'reorder-before' ? 'insertBefore' : intent === 'reorder-after' ? 'insertAfter' : '';
  return <div ref={setNodeRef} className={`catTree__row${isDragging ? ' catTree__row--dragging' : ''}${modifier ? ` catTree__row--${modifier}` : ''}`}
    style={{ paddingLeft: `${Math.min(row.depth, 5) * 16 + 8}px` }} data-category-id={row.category.categoryId} data-depth={row.depth}>
    <DragHandle listeners={listeners} attributes={attributes} label={`Move ${row.category.name}`} />
    <button type="button" className="catTree__edit" disabled={disabled} onClick={() => onEdit(row.category.categoryId)}>
      <span className="catTree__dot" style={{ backgroundColor: getAccentColor(row.rootIndex).start }} aria-hidden="true" />
      <span className="catTree__name">{row.category.name}</span>
      {row.hasChildren && <span className="catTree__chevron" aria-hidden="true">&rsaquo;</span>}
    </button>
  </div>;
}

export default function CategoryManagerTree({ categories, onEditCategory, onAdd, onReorder, onReparent, toolbarSlot, disabled = false }: CategoryManagerTreeProps) {
  const helpId = useId();
  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 8 } }), useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }));
  const rows = useMemo(() => new CategoryHierarchy(categories.filter(category => !category.isSystem)).rows, [categories]);
  const drag = useCategoryTreeDrag(categories, disabled, move => {
    if (move.type === 'reorder') onReorder(move.updates);
    else onReparent(move.categoryId, move.parentId, move.insertAtCategoryId, move.insertAfter);
  });
  const activeRow = rows.find(row => row.category.categoryId === drag.activeId);
  return <div className="catTree" aria-describedby={helpId}>
    <div className="catTree__toolbar">
      <span className="catTree__title">Categories</span>
      <div className="catTree__toolbarActions">
        <button autoFocus type="button" className="catTree__addBtn" disabled={disabled} onClick={onAdd} aria-label="Add category">+ Add</button>
        {toolbarSlot}
      </div>
    </div>
    <p id={helpId} className="catTree__help">Drag to reorder or nest. With the keyboard, use Space and the arrow keys to reorder; edit a category to choose its parent.</p>
    <DndContext sensors={sensors} collisionDetection={categoryCollisionDetection} onDragStart={drag.start} onDragMove={drag.over}
      onDragOver={drag.over} onDragEnd={drag.end} onDragCancel={drag.cancel} measuring={{ droppable: { strategy: MeasuringStrategy.Always } }}>
      <SortableContext items={rows.map(row => String(row.category.categoryId))}>
        <div className="catTree__list">
          {rows.length === 0 && <p className="catTree__empty">No categories yet</p>}
          {rows.map(row => <SortableRow key={row.category.categoryId} row={row} onEdit={onEditCategory} disabled={disabled}
            intent={drag.preview?.targetId === row.category.categoryId ? drag.preview.intent : null} />)}
          <RootDropZone disabled={disabled} />
        </div>
      </SortableContext>
      <DragOverlay>{activeRow && <div className="catTree__row catTree__row--overlay" aria-hidden="true">
        <span className="catTree__dot" style={{ backgroundColor: getAccentColor(activeRow.rootIndex).start }} />
        <span className="catTree__name">{activeRow.category.name}</span>
      </div>}</DragOverlay>
    </DndContext>
  </div>;
}
