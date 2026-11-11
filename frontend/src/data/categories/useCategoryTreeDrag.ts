import { useState } from 'react';
import { closestCenter, pointerWithin, type CollisionDetection, type DragMoveEvent, type DragStartEvent } from '@dnd-kit/core';
import type { Category } from '../../utils/types';
import { getDropIntent, resolveCategoryDrop, type CategoryMove, type DropIntent } from './categoryDrop';

// pointerWithin has no collision for keyboard input, which has no pointer coordinates.
export const categoryCollisionDetection: CollisionDetection = args => args.pointerCoordinates ? pointerWithin(args) : closestCenter(args);

export function useCategoryTreeDrag(categories: Category[], disabled: boolean, onMove: (move: CategoryMove) => void) {
  const [activeId, setActiveId] = useState<number | null>(null);
  const [preview, setPreview] = useState<{ targetId: number | 'root-drop-zone'; intent: DropIntent } | null>(null);

  const resolve = (event: DragMoveEvent) => {
    if (disabled || !event.over) return null;
    const targetId: number | 'root-drop-zone' = event.over.id === 'root-drop-zone' ? 'root-drop-zone' : Number(event.over.id);
    const activator = event.activatorEvent;
    let intent: DropIntent;
    if (activator instanceof KeyboardEvent) intent = event.delta.y > 0 ? 'reorder-after' : 'reorder-before';
    else if ('clientY' in activator) intent = getDropIntent(event.over.rect, Number(activator.clientY) + event.delta.y);
    else return null;
    const move = resolveCategoryDrop(categories, Number(event.active.id), targetId, intent);
    return move ? { targetId, intent, move } : null;
  };

  const cancel = () => { setActiveId(null); setPreview(null); };
  const start = (event: DragStartEvent) => {
    if (!disabled) { setActiveId(Number(event.active.id)); setPreview(null); }
  };
  const over = (event: DragMoveEvent) => { setPreview(resolve(event)); };
  const end = (event: DragMoveEvent) => {
    const result = resolve(event);
    cancel();
    if (result) onMove(result.move);
  };
  return { activeId, preview, start, over, end, cancel };
}
