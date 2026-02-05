import { useMemo } from 'react';
import {
  DragEndEvent,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
} from '@dnd-kit/core';
import { arrayMove, sortableKeyboardCoordinates } from '@dnd-kit/sortable';

export interface SortableItem {
  id: string;
  category: string;
}

export interface CategoryGroup<T extends SortableItem> {
  category: string;
  items: T[];
}

export function useCategorySortable<T extends SortableItem>(
  items: T[],
  onChange: (items: T[]) => void
) {
  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: {
        distance: 8,
      },
    }),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
    })
  );

  const groupedItems = useMemo(() => {
    return groupByCategory(items);
  }, [items]);

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    if (!over || active.id === over.id) return;

    const activeItem = items.find((p) => p.id === active.id);
    const overItem = items.find((p) => p.id === over.id);

    // Reject cross-category drops
    if (activeItem?.category !== overItem?.category) return;

    const oldIndex = items.findIndex((p) => p.id === active.id);
    const newIndex = items.findIndex((p) => p.id === over.id);

    onChange(arrayMove(items, oldIndex, newIndex));
  };

  return {
    sensors,
    groupedItems,
    handleDragEnd,
  };
}

export function groupByCategory<T extends SortableItem>(
  items: T[]
): CategoryGroup<T>[] {
  const groups: Map<string, T[]> = new Map();

  for (const item of items) {
    const category = item.category || 'Uncategorized';
    if (!groups.has(category)) {
      groups.set(category, []);
    }
    groups.get(category)!.push(item);
  }

  return Array.from(groups.entries()).map(([category, groupItems]) => ({
    category,
    items: groupItems,
  }));
}
