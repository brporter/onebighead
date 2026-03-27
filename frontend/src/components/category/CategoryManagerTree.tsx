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
 * Determine drop intent based on pointer position relative to the over element.
 * Center 40% = reparent, top 30% = insert before, bottom 30% = insert after.
 */
function getDropIntent(overRect: DOMRect, pointerY: number): DropIntent {
  const relativeY = pointerY - overRect.top;
  const ratio = relativeY / overRect.height;
  if (ratio < 0.3) return 'reorder-before';
  if (ratio > 0.7) return 'reorder-after';
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

  // Track pointer position at document level for reliable drop intent detection during drag
  useEffect(() => {
    const handlePointerMove = (e: PointerEvent) => {
      pointerYRef.current = e.clientY;
    };
    document.addEventListener('pointermove', handlePointerMove);
    return () => document.removeEventListener('pointermove', handlePointerMove);
  }, []);

  const handleDragStart = useCallback((event: DragStartEvent) => {
    setActiveId(String(event.active.id));
  }, []);

  const handleDragOver = useCallback((event: DragOverEvent) => {
    const { active, over } = event;
    if (!over || active.id === over.id) {
      setOverTargetId(null);
      setDropIntent(null);
      return;
    }

    if (over.id === 'root-drop-zone') {
      setOverTargetId(null);
      setDropIntent(null);
      return;
    }

    const overId = Number(over.id);

    // Prevent circular: can't drop onto self or descendant
    if (disabledTargetIds.has(overId)) {
      setOverTargetId(null);
      setDropIntent(null);
      return;
    }

    // Determine intent from pointer position using dnd-kit's rect
    const overRect = over.rect;
    let intent: DropIntent = 'reparent';
    if (overRect) {
      intent = getDropIntent(
        { top: overRect.top, height: overRect.height } as DOMRect,
        pointerYRef.current
      );
    }

    setOverTargetId(overId);
    setDropIntent(intent);
  }, [disabledTargetIds]);

  const handleDragEnd = useCallback((event: DragEndEvent) => {
    const { active, over } = event;
    const currentIntent = dropIntent;

    setActiveId(null);
    setOverTargetId(null);
    setDropIntent(null);

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

    if (currentIntent === 'reparent') {
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
  }, [categories, disabledTargetIds, dropIntent, onReorder, onReparent]);

  const handleDragCancel = useCallback(() => {
    setActiveId(null);
    setOverTargetId(null);
    setDropIntent(null);
  }, []);

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
