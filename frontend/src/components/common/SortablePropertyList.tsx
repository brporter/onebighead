import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { DndContext, closestCenter, DragOverlay } from '@dnd-kit/core';
import { SortableContext, verticalListSortingStrategy, useSortable } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { DragHandle } from './DragHandle';
import { useCategorySortable } from '../../hooks/useCategorySortable';

// Base property interface - all properties must have these
export interface BaseProperty {
  id: string;
  category: string;
  name: string;
}

// Extended property with optional value (for item properties)
export interface PropertyWithValue extends BaseProperty {
  value: string;
}

// Field configuration for the property row
export interface FieldConfig {
  field: 'category' | 'name' | 'value';
  placeholder: string;
  label?: string;
  className?: string;
  datalistId?: string;
}

interface SortablePropertyRowProps<T extends BaseProperty> {
  property: T;
  fields: FieldConfig[];
  rowClassName: string;
  draggingClassName: string;
  inputClassName: string;
  removeButtonClassName: string;
  onFieldChange: (id: string, field: keyof T, value: string) => void;
  onFieldBlur?: (id: string, field: keyof T) => void;
  onRemove: (id: string) => void;
  onCategoryTab?: (id: string) => void;
}

function SortablePropertyRow<T extends BaseProperty>({
  property,
  fields,
  rowClassName,
  draggingClassName,
  inputClassName,
  removeButtonClassName,
  onFieldChange,
  onFieldBlur,
  onRemove,
  onCategoryTab,
}: SortablePropertyRowProps<T>) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id: property.id });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
  };

  return (
    <div
      ref={setNodeRef}
      style={style}
      className={`${rowClassName} ${isDragging ? draggingClassName : ''}`}
    >
      <DragHandle listeners={listeners} attributes={attributes} />
      {fields.map((fieldConfig) => (
        <input
          key={fieldConfig.field}
          type="text"
          className={`${inputClassName} ${fieldConfig.className || ''}`}
          placeholder={fieldConfig.placeholder}
          aria-label={fieldConfig.label}
          value={(property as unknown as Record<string, string>)[fieldConfig.field] || ''}
          onChange={(e) => onFieldChange(property.id, fieldConfig.field as keyof T, e.target.value)}
          onBlur={() => onFieldBlur?.(property.id, fieldConfig.field as keyof T)}
          onKeyDown={fieldConfig.field === 'category' ? (e) => {
            if (e.key === 'Tab' && !e.shiftKey) {
              onCategoryTab?.(property.id);
            }
          } : undefined}
          list={fieldConfig.datalistId}
          data-property-id={property.id}
          data-field={fieldConfig.field}
        />
      ))}
      <button
        type="button"
        className={removeButtonClassName}
        onClick={() => onRemove(property.id)}
        aria-label="Remove property"
      >
        ×
      </button>
    </div>
  );
}

interface SortablePropertyListProps<T extends BaseProperty> {
  properties: T[];
  fields: FieldConfig[];
  classNames: {
    list: string;
    categoryHeader: string;
    row: string;
    rowDragging: string;
    rowOverlay: string;
    input: string;
    removeButton: string;
  };
  onPropertiesChange: (properties: T[]) => void;
  onFieldChange: (id: string, field: keyof T, value: string) => void;
  onFieldBlur?: (id: string, field: keyof T) => void;
  onRemove: (id: string) => void;
  onCategoryTab?: (id: string) => void;
}

export function SortablePropertyList<T extends BaseProperty>({
  properties,
  fields,
  classNames,
  onPropertiesChange,
  onFieldChange,
  onFieldBlur,
  onRemove,
  onCategoryTab,
}: SortablePropertyListProps<T>) {
  const [activeId, setActiveId] = useState<string | null>(null);
  // Immutable record of stable grouping categories (only updated on blur, not on each keystroke)
  const [groupingCategories, setGroupingCategories] = useState<Record<string, string>>({});
  // Track which input to focus after a re-grouping render
  const focusTargetRef = useRef<{ id: string; field: string } | null>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Initialize grouping categories for new properties
  const syncedCategories = useMemo(() => {
    const result = { ...groupingCategories };
    let changed = false;
    // Add new properties
    properties.forEach((prop) => {
      if (!(prop.id in result)) {
        result[prop.id] = prop.category || 'Uncategorized';
        changed = true;
      }
    });
    // Clean up removed properties
    const currentIds = new Set(properties.map((p) => p.id));
    for (const id of Object.keys(result)) {
      if (!currentIds.has(id)) {
        delete result[id];
        changed = true;
      }
    }
    return changed ? result : groupingCategories;
  }, [properties, groupingCategories]);

  // Sync state if new properties were added/removed
  if (syncedCategories !== groupingCategories) {
    setGroupingCategories(syncedCategories);
  }

  // Handle category blur - update stable grouping category
  const handleCategoryBlur = useCallback((id: string) => {
    const prop = properties.find((p) => p.id === id);
    const newCategory = prop?.category || 'Uncategorized';
    setGroupingCategories((prev) => ({ ...prev, [id]: newCategory }));
  }, [properties]);

  // Wrap onFieldBlur to also handle category grouping updates
  const handleFieldBlur = useCallback((id: string, field: keyof T) => {
    if (field === 'category') {
      handleCategoryBlur(id);
    }
    onFieldBlur?.(id, field);
  }, [handleCategoryBlur, onFieldBlur]);

  // Handle Tab on category field - schedule focus to name field after re-grouping
  const handleCategoryTab = useCallback((id: string) => {
    focusTargetRef.current = { id, field: 'name' };
    onCategoryTab?.(id);
  }, [onCategoryTab]);

  // Restore focus after re-grouping re-render
  useEffect(() => {
    if (focusTargetRef.current) {
      const { id, field } = focusTargetRef.current;
      focusTargetRef.current = null;
      const input = listRef.current!.querySelector<HTMLInputElement>(
        `[data-property-id="${id}"][data-field="${field}"]`
      );
      input?.focus();
    }
  });

  // Create sortable items with stable grouping categories
  const sortableItems = useMemo(() =>
    properties.map((p) => ({
      ...p,
      category: groupingCategories[p.id] || 'Uncategorized',
    })),
    [properties, groupingCategories]
  );

  const { sensors, groupedItems, handleDragEnd } = useCategorySortable(
    sortableItems,
    (items) => {
      // Update grouping categories to match new order
      const updated: Record<string, string> = {};
      items.forEach((item) => {
        updated[item.id] = item.category;
      });
      setGroupingCategories((prev) => ({ ...prev, ...updated }));
      // Sorting changes only order. Preserve original values, including an actual
      // category named "Uncategorized", rather than persisting display labels.
      const reorderedProperties = items.map(item => properties.find(property => property.id === item.id)!);
      onPropertiesChange(reorderedProperties);
    }
  );

  const activeProperty = activeId ? properties.find((p) => p.id === activeId) : null;

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={closestCenter}
      onDragStart={(event) => setActiveId(event.active.id as string)}
      onDragEnd={(event) => {
        handleDragEnd(event);
        setActiveId(null);
      }}
      onDragCancel={() => setActiveId(null)}
    >
      <div ref={listRef} className={classNames.list}>
        <SortableContext items={groupedItems.flatMap(group => group.items.map(property => property.id))} strategy={verticalListSortingStrategy}>
          {/* Rows share a stable parent so regrouping never replaces a focused input. */}
          {groupedItems.flatMap(group => [
            <div key={`category:${group.category}`} className={classNames.categoryHeader}>{group.category}</div>,
            ...group.items.map((prop) => {
                // Find the original property to get the actual category value (not the grouping one)
                const originalProp = properties.find((p) => p.id === prop.id)!;
                return (
                  <SortablePropertyRow
                    key={`property:${prop.id}`}
                    property={originalProp}
                    fields={fields}
                    rowClassName={classNames.row}
                    draggingClassName={classNames.rowDragging}
                    inputClassName={classNames.input}
                    removeButtonClassName={classNames.removeButton}
                    onFieldChange={onFieldChange}
                    onFieldBlur={handleFieldBlur}
                    onRemove={onRemove}
                    onCategoryTab={handleCategoryTab}
                  />
                );
            }),
          ])}
        </SortableContext>
      </div>
      <DragOverlay>
        {activeProperty ? (
          <div className={`${classNames.row} ${classNames.rowOverlay}`}>
            <DragHandle />
            {fields.map((fieldConfig) => (
              <input
                key={fieldConfig.field}
                type="text"
                className={`${classNames.input} ${fieldConfig.className || ''}`}
                value={(activeProperty as unknown as Record<string, string>)[fieldConfig.field] || ''}
                readOnly
              />
            ))}
            <button type="button" className={classNames.removeButton}>×</button>
          </div>
        ) : null}
      </DragOverlay>
    </DndContext>
  );
}
