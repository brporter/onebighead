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
  verticalListSortingStrategy,
  useSortable,
  sortableKeyboardCoordinates,
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
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

const REPARENT_DWELL_MS = 300;

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
    transform,
    transition,
    isDragging,
  } = useSortable({
    id: String(row.category.categoryId),
    disabled: row.category.isSystem,
  });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
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
 * Determine reorder intent (before/after) based on pointer position.
 * Top half = insert before, bottom half = insert after.
 */
function getReorderIntent(overRect: { top: number; height: number }, pointerY: number): DropIntent {
  const relativeY = pointerY - overRect.top;
  const ratio = relativeY / overRect.height;
  return ratio < 0.5 ? 'reorder-before' : 'reorder-after';
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
  const dwellTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const dwellTargetRef = useRef<number | null>(null);

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

  // Track pointer position at document level for reliable intent detection during drag
  useEffect(() => {
    const handlePointerMove = (e: PointerEvent) => {
      pointerYRef.current = e.clientY;
    };
    document.addEventListener('pointermove', handlePointerMove);
    return () => document.removeEventListener('pointermove', handlePointerMove);
  }, []);

  // Clean up dwell timer on unmount
  useEffect(() => {
    return () => {
      if (dwellTimerRef.current) clearTimeout(dwellTimerRef.current);
    };
  }, []);

  const clearDwellTimer = useCallback(() => {
    if (dwellTimerRef.current) {
      clearTimeout(dwellTimerRef.current);
      dwellTimerRef.current = null;
    }
    dwellTargetRef.current = null;
  }, []);

  const setIntent = useCallback((intent: DropIntent) => {
    setDropIntent(intent);
    dropIntentRef.current = intent;
  }, []);

  const handleDragStart = useCallback((event: DragStartEvent) => {
    setActiveId(String(event.active.id));
  }, []);

  const handleDragOver = useCallback((event: DragOverEvent) => {
    const { active, over } = event;
    if (!over || active.id === over.id) {
      setOverTargetId(null);
      setIntent(null);
      clearDwellTimer();
      return;
    }

    if (over.id === 'root-drop-zone') {
      setOverTargetId(null);
      setIntent(null);
      clearDwellTimer();
      return;
    }

    const overId = Number(over.id);

    // Prevent circular: can't drop onto self or descendant
    if (disabledTargetIds.has(overId)) {
      setOverTargetId(null);
      setIntent(null);
      clearDwellTimer();
      return;
    }

    // Determine initial reorder intent (before/after based on top/bottom half)
    const overRect = over.rect;
    let intent: DropIntent = 'reorder-after';
    if (overRect && overRect.height > 0) {
      intent = getReorderIntent(overRect, pointerYRef.current);
    }

    setOverTargetId(overId);

    // If we're already dwelling on this target and intent is reparent, keep it
    if (dwellTargetRef.current === overId && dropIntentRef.current === 'reparent') {
      // Already showing reparent for this target — keep it
      return;
    }

    // If this is a new target, reset dwell timer and show reorder intent
    if (dwellTargetRef.current !== overId) {
      clearDwellTimer();
      dwellTargetRef.current = overId;
      setIntent(intent);

      // Start dwell timer — after REPARENT_DWELL_MS, switch to reparent
      dwellTimerRef.current = setTimeout(() => {
        setDropIntent('reparent');
        dropIntentRef.current = 'reparent';
      }, REPARENT_DWELL_MS);
    } else {
      // Same target, still waiting for dwell — update reorder direction
      setIntent(intent);
    }
  }, [disabledTargetIds, setIntent, clearDwellTimer]);

  const handleDragEnd = useCallback((event: DragEndEvent) => {
    const { active, over } = event;

    setActiveId(null);
    setOverTargetId(null);
    setIntent(null);
    clearDwellTimer();

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

    // Use the ref for the most current intent
    const finalIntent = dropIntentRef.current;

    if (finalIntent === 'reparent') {
      // Drop onto center = make child of the over item
      onReparent(activeItem.categoryId, overId);
    } else {
      // Drop on edge = positional move
      // If same parent, it's a simple reorder
      if (activeItem.parentCategoryId === overItem.parentCategoryId) {
        const updates = computeReorderUpdates(categories, activeItem.categoryId, overId);
        if (updates) {
          onReorder(updates);
        }
      } else {
        // Different parent: reparent to the over item's parent, then insert at the over item's position
        const newParentId = overItem.parentCategoryId;
        onReparent(activeItem.categoryId, newParentId);
      }
    }
  }, [categories, disabledTargetIds, onReorder, onReparent, setIntent, clearDwellTimer]);

  const handleDragCancel = useCallback(() => {
    setActiveId(null);
    setOverTargetId(null);
    setIntent(null);
    clearDwellTimer();
  }, [setIntent, clearDwellTimer]);

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
        <SortableContext items={sortableIds} strategy={verticalListSortingStrategy}>
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
