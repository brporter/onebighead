import { useState, useMemo, useCallback } from 'react';
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
          value={(property as unknown as Record<string, string>)[fieldConfig.field] || ''}
          onChange={(e) => onFieldChange(property.id, fieldConfig.field as keyof T, e.target.value)}
          onBlur={() => onFieldBlur?.(property.id, fieldConfig.field as keyof T)}
          list={fieldConfig.datalistId}
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
    categoryGroup: string;
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
}

export function SortablePropertyList<T extends BaseProperty>({
  properties,
  fields,
  classNames,
  onPropertiesChange,
  onFieldChange,
  onFieldBlur,
  onRemove,
}: SortablePropertyListProps<T>) {
  const [activeId, setActiveId] = useState<string | null>(null);
  // Counter to force re-render when grouping categories change
  const [groupingVersion, setGroupingVersion] = useState(0);
  // Track stable grouping categories (only updated on blur, not on each keystroke)
  const [groupingCategories] = useState<Map<string, string>>(() => new Map());

  // Initialize grouping categories for new properties
  useMemo(() => {
    properties.forEach((prop) => {
      if (!groupingCategories.has(prop.id)) {
        groupingCategories.set(prop.id, prop.category || 'Uncategorized');
      }
    });
    // Clean up removed properties
    const currentIds = new Set(properties.map((p) => p.id));
    groupingCategories.forEach((_, id) => {
      if (!currentIds.has(id)) {
        groupingCategories.delete(id);
      }
    });
  }, [properties, groupingCategories]);

  // Handle category blur - update stable grouping category
  const handleCategoryBlur = useCallback((id: string) => {
    const prop = properties.find((p) => p.id === id);
    groupingCategories.set(id, prop?.category || 'Uncategorized');
    setGroupingVersion((v) => v + 1);
  }, [properties, groupingCategories]);

  // Wrap onFieldBlur to also handle category grouping updates
  const handleFieldBlur = useCallback((id: string, field: keyof T) => {
    if (field === 'category') {
      handleCategoryBlur(id);
    }
    onFieldBlur?.(id, field);
  }, [handleCategoryBlur, onFieldBlur]);

  // Create sortable items with stable grouping categories
  const sortableItems = useMemo(() =>
    properties.map((p) => ({
      ...p,
      category: groupingCategories.get(p.id) || 'Uncategorized',
    })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [properties, groupingVersion]
  );

  const { sensors, groupedItems, handleDragEnd } = useCategorySortable(
    sortableItems,
    (items) => {
      // Update grouping categories to match new order
      items.forEach((item) => {
        groupingCategories.set(item.id, item.category || 'Uncategorized');
      });
      // Map back to original property type, restoring empty category if it was 'Uncategorized'
      const reorderedProperties = items.map((item) => {
        const original = properties.find((p) => p.id === item.id)!;
        return {
          ...original,
          category: item.category === 'Uncategorized' ? '' : item.category,
        } as T;
      });
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
      <div className={classNames.list}>
        {groupedItems.map((group) => (
          <div key={group.category} className={classNames.categoryGroup}>
            <div className={classNames.categoryHeader}>{group.category}</div>
            <SortableContext
              items={group.items.map((p) => p.id)}
              strategy={verticalListSortingStrategy}
            >
              {group.items.map((prop) => {
                // Find the original property to get the actual category value (not the grouping one)
                const originalProp = properties.find((p) => p.id === prop.id)!;
                return (
                  <SortablePropertyRow
                    key={prop.id}
                    property={originalProp}
                    fields={fields}
                    rowClassName={classNames.row}
                    draggingClassName={classNames.rowDragging}
                    inputClassName={classNames.input}
                    removeButtonClassName={classNames.removeButton}
                    onFieldChange={onFieldChange}
                    onFieldBlur={handleFieldBlur}
                    onRemove={onRemove}
                  />
                );
              })}
            </SortableContext>
          </div>
        ))}
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
