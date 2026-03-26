import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CategoryManagerTree from '../src/components/category/CategoryManagerTree';
import type { Category } from '../src/utils/types';
import { Visibility } from '../src/utils/types';

// Mock @dnd-kit/core
const mockUseDroppable = vi.fn(() => ({
  setNodeRef: vi.fn(),
  isOver: false,
  node: { current: null },
  over: null,
  active: null,
  rect: { current: null },
}));

vi.mock('@dnd-kit/core', () => ({
  DndContext: ({ children }: { children: React.ReactNode }) => <div data-testid="dnd-context">{children}</div>,
  DragOverlay: ({ children }: { children: React.ReactNode }) => <div data-testid="drag-overlay">{children}</div>,
  closestCenter: vi.fn(),
  useSensor: vi.fn(() => ({})),
  useSensors: vi.fn(() => []),
  PointerSensor: vi.fn(),
  KeyboardSensor: vi.fn(),
  useDroppable: (...args: unknown[]) => mockUseDroppable(...args),
}));

// Mock @dnd-kit/sortable
vi.mock('@dnd-kit/sortable', () => ({
  SortableContext: ({ children }: { children: React.ReactNode }) => <div data-testid="sortable-context">{children}</div>,
  verticalListSortingStrategy: 'vertical',
  sortableKeyboardCoordinates: vi.fn(),
  useSortable: vi.fn(() => ({
    attributes: { role: 'button', tabIndex: 0 },
    listeners: {},
    setNodeRef: vi.fn(),
    transform: null,
    transition: null,
    isDragging: false,
  })),
}));

// Mock @dnd-kit/utilities
vi.mock('@dnd-kit/utilities', () => ({
  CSS: { Transform: { toString: (val: unknown) => (val ? 'translate(0, 0)' : undefined) } },
}));

// Mock DragHandle
vi.mock('../src/components/common/DragHandle', () => ({
  DragHandle: ({ listeners, attributes }: { listeners?: unknown; attributes?: unknown }) => (
    <div data-testid="drag-handle" {...(attributes as object)} {...(listeners as object)} />
  ),
}));

const makeCategory = (overrides: Partial<Category> = {}): Category => ({
  workspaceId: 1,
  collectionId: 1,
  categoryId: 1,
  name: 'Test Category',
  description: '',
  parentCategoryId: null,
  isSystem: false,
  visibility: Visibility.Private,
  effectiveIsPublic: false,
  itemTemplateIds: [],
  sortOrder: 0,
  ...overrides,
});

// Hierarchy:
//   1: Cameras (root, sortOrder 0)
//     2: Film (child, sortOrder 0)
//     3: Digital (child, sortOrder 1)
//   4: Lenses (root, sortOrder 1)
//   5: Unassigned (root, system, sortOrder 2)
const mockCategories: Category[] = [
  makeCategory({ categoryId: 1, name: 'Cameras', parentCategoryId: null, sortOrder: 0 }),
  makeCategory({ categoryId: 2, name: 'Film', parentCategoryId: 1, sortOrder: 0 }),
  makeCategory({ categoryId: 3, name: 'Digital', parentCategoryId: 1, sortOrder: 1 }),
  makeCategory({ categoryId: 4, name: 'Lenses', parentCategoryId: null, sortOrder: 1 }),
  makeCategory({ categoryId: 5, name: 'Unassigned', parentCategoryId: null, isSystem: true, sortOrder: 2 }),
];

describe('CategoryManagerTree', () => {
  const defaultProps = {
    categories: mockCategories,
    selectedCategoryId: null as number | null,
    onSelect: vi.fn(),
    onAdd: vi.fn(),
    onSortClick: vi.fn(),
    onReorder: vi.fn(),
    onReparent: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('rendering hierarchy', () => {
    it('renders all categories in tree order', () => {
      render(<CategoryManagerTree {...defaultProps} />);

      expect(screen.getByText('Cameras')).toBeInTheDocument();
      expect(screen.getByText('Film')).toBeInTheDocument();
      expect(screen.getByText('Digital')).toBeInTheDocument();
      expect(screen.getByText('Lenses')).toBeInTheDocument();
      expect(screen.getByText('Unassigned')).toBeInTheDocument();
    });

    it('renders correct indentation for children', () => {
      const { container } = render(<CategoryManagerTree {...defaultProps} />);

      const rows = container.querySelectorAll('.catTree__row');
      // Cameras (depth 0) - no indent
      const camerasRow = Array.from(rows).find(r => r.textContent?.includes('Cameras'));
      expect(camerasRow?.getAttribute('data-depth')).toBe('0');

      // Film (depth 1) - indented
      const filmRow = Array.from(rows).find(r => r.textContent?.includes('Film'));
      expect(filmRow?.getAttribute('data-depth')).toBe('1');
    });

    it('shows chevron for parent categories', () => {
      const { container } = render(<CategoryManagerTree {...defaultProps} />);

      const rows = container.querySelectorAll('.catTree__row');
      const camerasRow = Array.from(rows).find(r => r.textContent?.includes('Cameras'));
      expect(camerasRow?.querySelector('.catTree__chevron')).toBeTruthy();

      // Lenses has no children, no chevron
      const lensesRow = Array.from(rows).find(r => r.textContent?.includes('Lenses'));
      expect(lensesRow?.querySelector('.catTree__chevron')).toBeFalsy();
    });

    it('shows accent color dots', () => {
      const { container } = render(<CategoryManagerTree {...defaultProps} />);

      const dots = container.querySelectorAll('.catTree__dot');
      expect(dots.length).toBeGreaterThan(0);
      // Each dot should have a background color style
      dots.forEach(dot => {
        expect((dot as HTMLElement).style.backgroundColor).toBeTruthy();
      });
    });
  });

  describe('selection', () => {
    it('highlights selected category with active styling', () => {
      const { container } = render(<CategoryManagerTree {...defaultProps} selectedCategoryId={2} />);

      const activeRow = container.querySelector('.catTree__row--active');
      expect(activeRow).toBeTruthy();
      expect(activeRow?.textContent).toContain('Film');
    });

    it('clicking a category calls onSelect', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(<CategoryManagerTree {...defaultProps} onSelect={handleSelect} />);

      await user.click(screen.getByText('Film'));
      expect(handleSelect).toHaveBeenCalledWith(2);
    });
  });

  describe('toolbar', () => {
    it('add button calls onAdd', async () => {
      const user = userEvent.setup();
      const handleAdd = vi.fn();
      render(<CategoryManagerTree {...defaultProps} onAdd={handleAdd} />);

      await user.click(screen.getByLabelText('Add category'));
      expect(handleAdd).toHaveBeenCalled();
    });

    it('sort button calls onSortClick', async () => {
      const user = userEvent.setup();
      const handleSort = vi.fn();
      render(<CategoryManagerTree {...defaultProps} onSortClick={handleSort} />);

      await user.click(screen.getByLabelText('Sort categories'));
      expect(handleSort).toHaveBeenCalled();
    });
  });

  describe('drag handles', () => {
    it('renders drag handle on non-system category rows', () => {
      const { container } = render(<CategoryManagerTree {...defaultProps} />);

      const rows = container.querySelectorAll('.catTree__row');
      const nonSystemRows = Array.from(rows).filter(r => !r.textContent?.includes('Unassigned'));
      nonSystemRows.forEach(row => {
        expect(row.querySelector('[data-testid="drag-handle"]')).toBeTruthy();
      });
    });

    it('does not render drag handle for system categories', () => {
      const { container } = render(<CategoryManagerTree {...defaultProps} />);

      const rows = container.querySelectorAll('.catTree__row');
      const systemRow = Array.from(rows).find(r => r.textContent?.includes('Unassigned'));
      expect(systemRow?.querySelector('[data-testid="drag-handle"]')).toBeFalsy();
    });
  });

  describe('root level drop zone', () => {
    it('renders root level drop zone for reparenting to root', () => {
      const { container } = render(<CategoryManagerTree {...defaultProps} />);

      expect(container.querySelector('.catTree__rootDropZone')).toBeTruthy();
    });

    it('uses useDroppable hook with root-drop-zone id', () => {
      render(<CategoryManagerTree {...defaultProps} />);

      expect(mockUseDroppable).toHaveBeenCalledWith({ id: 'root-drop-zone' });
    });

    it('applies --over modifier class when isOver is true', () => {
      mockUseDroppable.mockReturnValueOnce({
        setNodeRef: vi.fn(),
        isOver: true,
        node: { current: null },
        over: null,
        active: null,
        rect: { current: null },
      });

      const { container } = render(<CategoryManagerTree {...defaultProps} />);

      expect(container.querySelector('.catTree__rootDropZone--over')).toBeTruthy();
    });
  });

  describe('empty state', () => {
    it('renders empty message when no categories', () => {
      render(<CategoryManagerTree {...defaultProps} categories={[]} />);

      expect(screen.getByText('No categories yet')).toBeInTheDocument();
    });
  });

  describe('DndContext wrapping', () => {
    it('wraps tree in DndContext and SortableContext', () => {
      render(<CategoryManagerTree {...defaultProps} />);

      expect(screen.getByTestId('dnd-context')).toBeInTheDocument();
      expect(screen.getByTestId('sortable-context')).toBeInTheDocument();
    });

    it('renders DragOverlay', () => {
      render(<CategoryManagerTree {...defaultProps} />);

      expect(screen.getByTestId('drag-overlay')).toBeInTheDocument();
    });
  });
});
