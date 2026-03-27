import React, { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import {
  DndContext,
  DragOverlay,
  DragStartEvent,
  DragEndEvent,
  DragOverEvent,
  PointerSensor,
  KeyboardSensor,
  useSensor,
  useSensors,
  useDroppable,
  pointerWithin,
  MeasuringStrategy,
} from '@dnd-kit/core';
import {
  SortableContext,
  useSortable,
  sortableKeyboardCoordinates,
} from '@dnd-kit/sortable';
import type { Category } from '../../utils/types';
import { getAccentColor } from '../../utils/accentColors';
import { DragHandle } from '../common/DragHandle';
import {
  buildCategoryTree,
  flattenWithIndent,
  getDescendantIds,
  computeReorderUpdates,
} from './categoryManagerTreeUtils';
import type { FlatRow } from './categoryManagerTreeUtils';

export type DropIntent = 'reparent' | 'reorder-before' | 'reorder-after' | null;

export interface CategoryManagerTreeProps {
  categories: Category[];
  onEditCategory: (categoryId: number) => void;
  onAdd: () => void;
  onReorder: (updates: { categoryId: number; sortOrder: number }[]) => void;
  onReparent: (categoryId: number, newParentId: number | null) => void;
  toolbarSlot?: React.ReactNode;
}

function RootDropZone() {
  const { setNodeRef, isOver } = useDroppable({ id: 'root-drop-zone' });
  return (
    <div
      ref={setNodeRef}
      className={`catTree__rootDropZone${isOver ? ' catTree__rootDropZone--over' : ''}`}
    >
      Move here to make root level
    </div>
  );
}

interface SortableRowProps {
  row: FlatRow;
  onEditCategory: (categoryId: number) => void;
  dropIntent: DropIntent;
  isDisabledTarget: boolean;
}

function SortableRow({ row, onEditCategory, dropIntent, isDisabledTarget }: SortableRowProps) {
  const {
    attributes,
    listeners,
    setNodeRef,
    isDragging,
  } = useSortable({
    id: String(row.category.categoryId),
    disabled: row.category.isSystem,
    // Disable animated layout shifts — rows stay in place during drag
    animateLayoutChanges: () => false,
  });

  const style = {
    paddingLeft: `${row.depth * 20 + 8}px`,
  };

  const accentColor = getAccentColor(row.rootIndex);

  let className = 'catTree__row';
  if (isDragging) className += ' catTree__row--dragging';
  if (!isDisabledTarget && dropIntent === 'reparent') className += ' catTree__row--dropTarget';
  if (!isDisabledTarget && dropIntent === 'reorder-before') className += ' catTree__row--insertBefore';
  if (!isDisabledTarget && dropIntent === 'reorder-after') className += ' catTree__row--insertAfter';

  return (
    <div
      ref={setNodeRef}
      style={style}
      className={className}
      data-category-id={String(row.category.categoryId)}
      data-depth={String(row.depth)}
      onClick={() => onEditCategory(row.category.categoryId)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onEditCategory(row.category.categoryId);
        }
      }}
    >
      {!row.category.isSystem && (
        <DragHandle listeners={listeners} attributes={attributes} />
      )}
      <span
        className="catTree__dot"
        style={{ backgroundColor: accentColor.start }}
        aria-hidden="true"
      />
      <span className="catTree__name">{row.category.name}</span>
      {row.hasChildren && (
        <span className="catTree__chevron" aria-hidden="true">&rsaquo;</span>
      )}
    </div>
  );
}

/**
 * Determine drop intent from pointer position within the over element.
 * Top 10% = reorder-before, bottom 10% = reorder-after, center 80% = reparent.
 */
function getDropIntent(overRect: { top: number; height: number }, pointerY: number): DropIntent {
  const relativeY = pointerY - overRect.top;
  const ratio = relativeY / overRect.height;
  if (ratio <= 0.1) return 'reorder-before';
  if (ratio >= 0.9) return 'reorder-after';
  return 'reparent';
}

function CategoryManagerTree({
  categories,
  onEditCategory,
  onAdd,
  onReorder,
  onReparent,
  toolbarSlot,
}: CategoryManagerTreeProps) {
  const [activeId, setActiveId] = useState<string | null>(null);
  const [overTargetId, setOverTargetId] = useState<number | null>(null);
  const [dropIntent, setDropIntent] = useState<DropIntent>(null);
  const dropIntentRef = useRef<DropIntent>(null);
  const pointerYRef = useRef<number>(0);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 8 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  );

  const nonSystemCategories = useMemo(
    () => categories.filter(c => !c.isSystem),
    [categories]
  );

  const flatRows = useMemo(() => {
    const tree = buildCategoryTree(nonSystemCategories);
    const result: FlatRow[] = [];
    tree.forEach((rootNode, rootIdx) => {
      result.push(...flattenWithIndent([rootNode], rootIdx));
    });
    return result;
  }, [nonSystemCategories]);

  const sortableIds = useMemo(
    () => flatRows.map(r => String(r.category.categoryId)),
    [flatRows]
  );

  // Compute descendants of active item for circular ref prevention
  const disabledTargetIds = useMemo(() => {
    if (!activeId) return new Set<number>();
    const id = Number(activeId);
    const descendants = getDescendantIds(categories, id);
    descendants.add(id);
    return descendants;
  }, [activeId, categories]);

  const activeIdRef = useRef<string | null>(null);
  const overTargetIdRef = useRef<number | null>(null);
  const disabledTargetIdsRef = useRef(disabledTargetIds);
  useEffect(() => {
    disabledTargetIdsRef.current = disabledTargetIds;
  }, [disabledTargetIds]);

  const setIntent = useCallback((targetId: number | null, intent: DropIntent) => {
    setOverTargetId(targetId);
    overTargetIdRef.current = targetId;
    setDropIntent(intent);
    dropIntentRef.current = intent;
  }, []);

  // Continuously update drop intent on every pointer move during drag
  useEffect(() => {
    const handlePointerMove = (e: PointerEvent) => {
      pointerYRef.current = e.clientY;

      // Only compute intent during an active drag
      if (!activeIdRef.current) return;

      // Find the category row under the pointer
      const elements = document.elementsFromPoint(e.clientX, e.clientY);
      const rowEl = elements.find(el => el.classList.contains('catTree__row') && el.getAttribute('data-category-id'));

      if (!rowEl) {
        // Pointer is not over any row
        if (overTargetIdRef.current !== null) {
          setIntent(null, null);
        }
        return;
      }

      const catId = Number(rowEl.getAttribute('data-category-id'));

      // Don't target self or descendants
      if (disabledTargetIdsRef.current.has(catId)) {
        if (overTargetIdRef.current !== null) {
          setIntent(null, null);
        }
        return;
      }

      const rect = rowEl.getBoundingClientRect();
      const intent = getDropIntent(rect, e.clientY);
      setIntent(catId, intent);
    };

    document.addEventListener('pointermove', handlePointerMove);
    return () => document.removeEventListener('pointermove', handlePointerMove);
  }, [setIntent]);

  const handleDragStart = useCallback((event: DragStartEvent) => {
    const id = String(event.active.id);
    setActiveId(id);
    activeIdRef.current = id;
  }, []);

  // handleDragOver still needed for dnd-kit's collision detection (determines `over` in handleDragEnd)
  // but visual intent is driven by the pointermove handler above
  const handleDragOver = useCallback(() => {
    // Visual feedback is handled by the pointermove listener
  }, []);

  const handleDragEnd = useCallback((event: DragEndEvent) => {
    const { active, over } = event;

    setActiveId(null);
    activeIdRef.current = null;
    setIntent(null, null);

    if (!over) return;

    const activeItem = categories.find(c => c.categoryId === Number(active.id));
    if (!activeItem) return;

    // Drop onto root zone
    if (over.id === 'root-drop-zone') {
      if (activeItem.parentCategoryId !== null) {
        onReparent(activeItem.categoryId, null);
      }
      return;
    }

    const overId = Number(over.id);
    const overItem = categories.find(c => c.categoryId === overId);
    if (!overItem || active.id === over.id) return;

    // Prevent circular reference
    if (disabledTargetIds.has(overId)) return;

    // Use the intent from our continuous pointer tracking
    const finalIntent = dropIntentRef.current;

    if (finalIntent === 'reparent') {
      // Drop onto center = make child of the over item
      onReparent(activeItem.categoryId, overId);
    } else {
      // Drop on edge = positional move
      if (activeItem.parentCategoryId === overItem.parentCategoryId) {
        const updates = computeReorderUpdates(categories, activeItem.categoryId, overId);
        if (updates) {
          onReorder(updates);
        }
      } else {
        // Different parent: reparent to the over item's parent
        const newParentId = overItem.parentCategoryId;
        onReparent(activeItem.categoryId, newParentId);
      }
    }
  }, [categories, disabledTargetIds, onReorder, onReparent, setIntent]);

  const handleDragCancel = useCallback(() => {
    setActiveId(null);
    activeIdRef.current = null;
    setIntent(null, null);
  }, [setIntent]);

  const activeRow = activeId
    ? flatRows.find(r => String(r.category.categoryId) === activeId)
    : null;

  return (
    <div className="catTree">
      <div className="catTree__toolbar">
        <span className="catTree__title">Categories</span>
        <div className="catTree__toolbarActions">
          <button
            type="button"
            className="catTree__addBtn"
            onClick={onAdd}
            aria-label="Add category"
          >
            +
          </button>
          {toolbarSlot}
        </div>
      </div>

      <DndContext
        sensors={sensors}
        collisionDetection={pointerWithin}
        onDragStart={handleDragStart}
        onDragOver={handleDragOver}
        onDragEnd={handleDragEnd}
        onDragCancel={handleDragCancel}
        measuring={{ droppable: { strategy: MeasuringStrategy.Always } }}
      >
        <SortableContext items={sortableIds}>
          <div className="catTree__list">
            {flatRows.length === 0 && (
              <p className="catTree__empty">No categories yet</p>
            )}
            {flatRows.map((row) => {
              const rowId = row.category.categoryId;
              const rowDropIntent = overTargetId === rowId ? dropIntent : null;
              return (
                <SortableRow
                  key={rowId}
                  row={row}
                  onEditCategory={onEditCategory}
                  dropIntent={rowDropIntent}
                  isDisabledTarget={disabledTargetIds.has(rowId)}
                />
              );
            })}
            <RootDropZone />
          </div>
        </SortableContext>

        <DragOverlay>
          {activeRow ? (
            <div className="catTree__row catTree__row--overlay">
              <DragHandle />
              <span
                className="catTree__dot"
                style={{ backgroundColor: getAccentColor(activeRow.rootIndex).start }}
                aria-hidden="true"
              />
              <span className="catTree__name">{activeRow.category.name}</span>
            </div>
          ) : null}
        </DragOverlay>
      </DndContext>
    </div>
  );
}

export default CategoryManagerTree;
