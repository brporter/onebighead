import { useState, useMemo, useCallback } from 'react';
import {
  DndContext,
  closestCenter,
  DragOverlay,
  DragStartEvent,
  DragEndEvent,
  DragOverEvent,
  PointerSensor,
  KeyboardSensor,
  useSensor,
  useSensors,
  useDroppable,
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
  determineReparentTarget,
} from './categoryManagerTreeUtils';
import type { FlatRow } from './categoryManagerTreeUtils';

export interface CategoryManagerTreeProps {
  categories: Category[];
  selectedCategoryId: number | null;
  onSelect: (categoryId: number) => void;
  onAdd: () => void;
  onSortClick: () => void;
  onReorder: (updates: { categoryId: number; sortOrder: number }[]) => void;
  onReparent: (categoryId: number, newParentId: number | null) => void;
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
  isSelected: boolean;
  onSelect: (categoryId: number) => void;
  isOverTarget: boolean;
  isDisabledTarget: boolean;
}

function SortableRow({ row, isSelected, onSelect, isOverTarget, isDisabledTarget }: SortableRowProps) {
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
  if (isSelected) className += ' catTree__row--active';
  if (isDragging) className += ' catTree__row--dragging';
  if (isOverTarget && !isDisabledTarget) className += ' catTree__row--dropTarget';

  return (
    <div
      ref={setNodeRef}
      style={style}
      className={className}
      data-depth={String(row.depth)}
      onClick={() => onSelect(row.category.categoryId)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect(row.category.categoryId);
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

function CategoryManagerTree({
  categories,
  selectedCategoryId,
  onSelect,
  onAdd,
  onSortClick,
  onReorder,
  onReparent,
}: CategoryManagerTreeProps) {
  const [activeId, setActiveId] = useState<string | null>(null);
  const [overParentId, setOverParentId] = useState<number | null | undefined>(undefined);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 8 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  );

  const flatRows = useMemo(() => {
    const tree = buildCategoryTree(categories);
    const result: FlatRow[] = [];
    tree.forEach((rootNode, rootIdx) => {
      result.push(...flattenWithIndent([rootNode], rootIdx));
    });
    return result;
  }, [categories]);

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

  const handleDragStart = useCallback((event: DragStartEvent) => {
    setActiveId(String(event.active.id));
  }, []);

  const handleDragOver = useCallback((event: DragOverEvent) => {
    const { active, over } = event;
    if (!over) {
      setOverParentId(undefined);
      return;
    }

    if (over.id === 'root-drop-zone') {
      setOverParentId(null);
      return;
    }

    const overId = Number(over.id);
    const activeItem = categories.find(c => c.categoryId === Number(active.id));
    const overItem = categories.find(c => c.categoryId === overId);

    if (!activeItem || !overItem) {
      setOverParentId(undefined);
      return;
    }

    // If same parent, this is a reorder, not a reparent
    if (activeItem.parentCategoryId === overItem.parentCategoryId) {
      setOverParentId(undefined);
      return;
    }

    // Prevent circular: can't drop onto self or descendant
    if (disabledTargetIds.has(overId)) {
      setOverParentId(undefined);
      return;
    }

    setOverParentId(overId);
  }, [categories, disabledTargetIds]);

  const handleDragEnd = useCallback((event: DragEndEvent) => {
    const { active, over } = event;
    setActiveId(null);
    setOverParentId(undefined);

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

    // Reparent: items have different parents
    if (activeItem.parentCategoryId !== overItem.parentCategoryId) {
      const target = determineReparentTarget(categories, activeItem.categoryId, overId);
      if (target !== undefined) {
        onReparent(activeItem.categoryId, target);
      }
      return;
    }

    // Reorder: same parent, compute new sort orders
    const updates = computeReorderUpdates(categories, activeItem.categoryId, overId);
    if (updates) {
      onReorder(updates);
    }
  }, [categories, disabledTargetIds, onReorder, onReparent]);

  const handleDragCancel = useCallback(() => {
    setActiveId(null);
    setOverParentId(undefined);
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
          <button
            type="button"
            className="catTree__sortBtn"
            onClick={onSortClick}
            aria-label="Sort categories"
          >
            Sort
          </button>
        </div>
      </div>

      <DndContext
        sensors={sensors}
        collisionDetection={closestCenter}
        onDragStart={handleDragStart}
        onDragOver={handleDragOver}
        onDragEnd={handleDragEnd}
        onDragCancel={handleDragCancel}
      >
        <SortableContext items={sortableIds} strategy={verticalListSortingStrategy}>
          <div className="catTree__list">
            {flatRows.length === 0 && (
              <p className="catTree__empty">No categories yet</p>
            )}
            {flatRows.map((row) => (
              <SortableRow
                key={row.category.categoryId}
                row={row}
                isSelected={row.category.categoryId === selectedCategoryId}
                onSelect={onSelect}
                isOverTarget={overParentId === row.category.categoryId}
                isDisabledTarget={disabledTargetIds.has(row.category.categoryId)}
              />
            ))}
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
