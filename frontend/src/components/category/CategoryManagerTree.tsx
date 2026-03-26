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
} from '@dnd-kit/core';
import {
  SortableContext,
  verticalListSortingStrategy,
  useSortable,
  sortableKeyboardCoordinates,
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import type { Category, CategoryNode } from '../../utils/types';
import { getAccentColor } from '../../utils/accentColors';
import { DragHandle } from '../common/DragHandle';

export interface CategoryManagerTreeProps {
  categories: Category[];
  selectedCategoryId: number | null;
  onSelect: (categoryId: number) => void;
  onAdd: () => void;
  onSortClick: () => void;
  onReorder: (updates: { categoryId: number; sortOrder: number }[]) => void;
  onReparent: (categoryId: number, newParentId: number | null) => void;
}

interface FlatRow {
  category: Category;
  depth: number;
  hasChildren: boolean;
  rootIndex: number;
}

function buildCategoryTree(categories: Category[]): CategoryNode[] {
  const map = new Map<number, CategoryNode>();
  const roots: CategoryNode[] = [];

  for (const cat of categories) {
    map.set(cat.categoryId, { ...cat, children: [] });
  }

  for (const cat of categories) {
    const node = map.get(cat.categoryId)!;
    if (cat.parentCategoryId === null) {
      roots.push(node);
    } else {
      const parent = map.get(cat.parentCategoryId);
      if (parent) {
        parent.children.push(node);
      } else {
        roots.push(node);
      }
    }
  }

  return roots;
}

function flattenWithIndent(
  nodes: CategoryNode[],
  rootIndex: number,
  depth = 0
): FlatRow[] {
  const result: FlatRow[] = [];
  for (const node of nodes) {
    result.push({
      category: node,
      depth,
      hasChildren: node.children.length > 0,
      rootIndex,
    });
    if (node.children.length > 0) {
      result.push(...flattenWithIndent(node.children, rootIndex, depth + 1));
    }
  }
  return result;
}

function getDescendantIds(categories: Category[], categoryId: number): Set<number> {
  const descendants = new Set<number>();
  const queue = [categoryId];
  while (queue.length > 0) {
    const current = queue.pop()!;
    for (const cat of categories) {
      if (cat.parentCategoryId === current && !descendants.has(cat.categoryId)) {
        descendants.add(cat.categoryId);
        queue.push(cat.categoryId);
      }
    }
  }
  return descendants;
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
      // If over item has children, reparent to be child of over item
      const overHasChildren = categories.some(c => c.parentCategoryId === overId);
      if (overHasChildren) {
        onReparent(activeItem.categoryId, overId);
      } else {
        // Reparent to the over item's parent
        onReparent(activeItem.categoryId, overItem.parentCategoryId);
      }
      return;
    }

    // Reorder: same parent, compute new sort orders
    const parentId = activeItem.parentCategoryId;
    const siblings = categories
      .filter(c => c.parentCategoryId === parentId && !c.isSystem)
      .sort((a, b) => a.sortOrder - b.sortOrder);

    const oldIndex = siblings.findIndex(c => c.categoryId === activeItem.categoryId);
    const newIndex = siblings.findIndex(c => c.categoryId === overId);
    if (oldIndex === -1 || newIndex === -1 || oldIndex === newIndex) return;

    const reordered = [...siblings];
    const [moved] = reordered.splice(oldIndex, 1);
    reordered.splice(newIndex, 0, moved);

    const updates = reordered.map((cat, idx) => ({
      categoryId: cat.categoryId,
      sortOrder: idx,
    }));
    onReorder(updates);
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
            <div className="catTree__rootDropZone" data-id="root-drop-zone">
              Move here to make root level
            </div>
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
