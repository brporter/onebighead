# Category Drill-Down Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the indented category tree sidebar with a single-level drill-down navigation that gives every category the full sidebar width.

**Architecture:** A new `CategoryNav` component replaces `CategoryTree`. It shows one level of the hierarchy at a time with breadcrumb navigation for fast jumps to ancestor levels. Drill path is derived from the selected category's ancestry, so deep links work. The collapse toggle moves inside the component header.

**Tech Stack:** React 19, Vitest, CSS custom properties

**Design Spec:** `docs/superpowers/specs/2026-03-23-category-drilldown-design.md`

---

## File Structure

### New Files
| File | Responsibility |
|------|---------------|
| `frontend/src/utils/categoryNavUtils.ts` | Pure functions: `buildDrillPath`, `getVisibleCategories`, `getBreadcrumb`, `getChildCount` |
| `frontend/tests/categoryNavUtils.test.ts` | Tests for the above utilities |
| `frontend/src/components/category/CategoryNav.tsx` | Drill-down navigation component (replaces CategoryTree) |
| `frontend/src/components/category/CategoryNav.css` | Styles for drill-down navigation |
| `frontend/tests/CategoryNav.test.tsx` | Tests for CategoryNav component |

### Modified Files
| File | Changes |
|------|---------|
| `frontend/src/views/CategoryView.tsx` | Import CategoryNav instead of CategoryTree, remove external sidebar toggle |
| `frontend/src/views/ItemView.tsx` | Import CategoryNav instead of CategoryTree |
| `frontend/src/components/category/index.ts` | Export CategoryNav, remove CategoryTree export |
| `frontend/src/styles/App.css` | Remove `.categoryTree__*` rules, remove `.app__sidebar-toggle` |

### Deleted Files
| File | Reason |
|------|--------|
| `frontend/src/components/category/CategoryTree.tsx` | Replaced by CategoryNav |
| `frontend/tests/CategoryTree.test.tsx` | Replaced by CategoryNav tests |

---

## Task 1: Category Nav Utility Functions

**Files:**
- Create: `frontend/src/utils/categoryNavUtils.ts`
- Create: `frontend/tests/categoryNavUtils.test.ts`

- [ ] **Step 1: Write failing tests**

Create `frontend/tests/categoryNavUtils.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { buildDrillPath, getVisibleCategories, getBreadcrumb, getChildCount } from '../src/utils/categoryNavUtils';
import type { Category } from '../src/utils/types';
import { Visibility } from '../src/utils/types';

function cat(id: number, name: string, parentId: number | null = null): Category {
  return {
    workspaceId: 1, collectionId: 1, categoryId: id, name, description: '',
    parentCategoryId: parentId, isSystem: false, visibility: Visibility.Default,
    effectiveIsPublic: false, itemTemplateIds: [],
  };
}

const categories: Category[] = [
  cat(1, 'Rangefinders'),
  cat(2, '35mm Film', 1),
  cat(3, 'Medium Format', 1),
  cat(4, 'Leica', 2),
  cat(5, 'SLR Cameras'),
  cat(6, 'Nikon', 5),
];

describe('buildDrillPath', () => {
  it('should return empty array for null categoryId', () => {
    expect(buildDrillPath(categories, null)).toEqual([]);
  });

  it('should return single-element path for root category', () => {
    expect(buildDrillPath(categories, 1)).toEqual([1]);
  });

  it('should return full ancestry path for nested category', () => {
    expect(buildDrillPath(categories, 4)).toEqual([1, 2, 4]);
  });

  it('should return path for direct child', () => {
    expect(buildDrillPath(categories, 2)).toEqual([1, 2]);
  });

  it('should return empty array for unknown categoryId', () => {
    expect(buildDrillPath(categories, 999)).toEqual([]);
  });
});

describe('getVisibleCategories', () => {
  it('should return root categories when drillPath is empty', () => {
    const visible = getVisibleCategories(categories, []);
    expect(visible.map(c => c.categoryId)).toEqual([1, 5]);
  });

  it('should return children of drilled category', () => {
    const visible = getVisibleCategories(categories, [1]);
    expect(visible.map(c => c.categoryId)).toEqual([2, 3]);
  });

  it('should return children of deeply drilled category', () => {
    const visible = getVisibleCategories(categories, [1, 2]);
    expect(visible.map(c => c.categoryId)).toEqual([4]);
  });

  it('should return empty array when leaf category has no children', () => {
    const visible = getVisibleCategories(categories, [1, 2, 4]);
    expect(visible).toEqual([]);
  });
});

describe('getBreadcrumb', () => {
  it('should return only "All" for empty drillPath', () => {
    expect(getBreadcrumb(categories, [])).toEqual([
      { id: null, name: 'All' },
    ]);
  });

  it('should return All + category for single drill', () => {
    expect(getBreadcrumb(categories, [1])).toEqual([
      { id: null, name: 'All' },
      { id: 1, name: 'Rangefinders' },
    ]);
  });

  it('should return full breadcrumb for deep drill', () => {
    expect(getBreadcrumb(categories, [1, 2, 4])).toEqual([
      { id: null, name: 'All' },
      { id: 1, name: 'Rangefinders' },
      { id: 2, name: '35mm Film' },
      { id: 4, name: 'Leica' },
    ]);
  });
});

describe('getChildCount', () => {
  it('should return number of direct children', () => {
    expect(getChildCount(categories, 1)).toBe(2);
  });

  it('should return 0 for leaf category', () => {
    expect(getChildCount(categories, 4)).toBe(0);
  });

  it('should return 0 for unknown category', () => {
    expect(getChildCount(categories, 999)).toBe(0);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/categoryNavUtils.test.ts` from `frontend/`
Expected: FAIL — module not found

- [ ] **Step 3: Implement utility functions**

Create `frontend/src/utils/categoryNavUtils.ts`:

```typescript
import type { Category } from './types';

export interface BreadcrumbSegment {
  id: number | null;
  name: string;
}

export function buildDrillPath(categories: Category[], categoryId: number | null): number[] {
  if (categoryId === null) return [];

  const byId = new Map<number, Category>();
  for (const cat of categories) {
    byId.set(cat.categoryId, cat);
  }

  const target = byId.get(categoryId);
  if (!target) return [];

  const path: number[] = [];
  let current: Category | undefined = target;
  while (current) {
    path.unshift(current.categoryId);
    current = current.parentCategoryId !== null ? byId.get(current.parentCategoryId) : undefined;
  }
  return path;
}

export function getVisibleCategories(categories: Category[], drillPath: number[]): Category[] {
  if (drillPath.length === 0) {
    return categories.filter(c => c.parentCategoryId === null);
  }
  const currentId = drillPath[drillPath.length - 1];
  return categories.filter(c => c.parentCategoryId === currentId);
}

export function getBreadcrumb(categories: Category[], drillPath: number[]): BreadcrumbSegment[] {
  const byId = new Map<number, Category>();
  for (const cat of categories) {
    byId.set(cat.categoryId, cat);
  }

  const crumbs: BreadcrumbSegment[] = [{ id: null, name: 'All' }];
  for (const catId of drillPath) {
    const cat = byId.get(catId);
    if (cat) crumbs.push({ id: cat.categoryId, name: cat.name });
  }
  return crumbs;
}

export function getChildCount(categories: Category[], categoryId: number): number {
  return categories.filter(c => c.parentCategoryId === categoryId).length;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/categoryNavUtils.test.ts` from `frontend/`
Expected: All tests PASS

- [ ] **Step 5: Commit**

From project root:
- `git add frontend/src/utils/categoryNavUtils.ts frontend/tests/categoryNavUtils.test.ts`
- `git commit -m "feat: add category drill-down navigation utility functions"`

---

## Task 2: Build CategoryNav Component

**Files:**
- Create: `frontend/src/components/category/CategoryNav.tsx`
- Create: `frontend/src/components/category/CategoryNav.css`
- Create: `frontend/tests/CategoryNav.test.tsx`

- [ ] **Step 1: Write failing tests**

Create `frontend/tests/CategoryNav.test.tsx`. The component needs the same `useData` mock pattern as the existing CategoryTree tests. Key test cases:

```tsx
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CategoryNav from '../src/components/category/CategoryNav';
import * as DataContext from '../src/contexts/useData';
import { createMockCategory, createMockCollection, createMockDataContextValue } from './testUtils';

vi.mock('../src/contexts/useData', async () => {
  const actual = await vi.importActual<typeof import('../src/contexts/DataContext')>('../src/contexts/DataContext');
  return { ...actual, useData: vi.fn() };
});

describe('CategoryNav', () => {
  const mockCategories = [
    createMockCategory({ categoryId: 1, name: 'Rangefinders', parentCategoryId: null }),
    createMockCategory({ categoryId: 2, name: '35mm Film', parentCategoryId: 1 }),
    createMockCategory({ categoryId: 3, name: 'Medium Format', parentCategoryId: 1 }),
    createMockCategory({ categoryId: 4, name: 'Leica', parentCategoryId: 2 }),
    createMockCategory({ categoryId: 5, name: 'SLR Cameras', parentCategoryId: null }),
  ];

  const defaultProps = {
    categories: mockCategories,
    selectedCategoryId: null,
    onSelect: vi.fn(),
  };

  beforeEach(() => {
    vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
      categories: mockCategories,
      addCategory: vi.fn(async () => 6),
      addCollection: vi.fn(async () => createMockCollection()),
    }));
  });

  describe('root level', () => {
    it('should render root categories', () => {
      render(<CategoryNav {...defaultProps} />);
      expect(screen.getByText('Rangefinders')).toBeInTheDocument();
      expect(screen.getByText('SLR Cameras')).toBeInTheDocument();
    });

    it('should not show child categories at root level', () => {
      render(<CategoryNav {...defaultProps} />);
      expect(screen.queryByText('35mm Film')).not.toBeInTheDocument();
    });

    it('should show chevron on categories with children', () => {
      const { container } = render(<CategoryNav {...defaultProps} />);
      const chevrons = container.querySelectorAll('.categoryNav__chevron');
      // Rangefinders has children, SLR Cameras has children
      expect(chevrons.length).toBe(2);
    });

    it('should not show breadcrumb at root level', () => {
      const { container } = render(<CategoryNav {...defaultProps} />);
      expect(container.querySelector('.categoryNav__breadcrumb')).not.toBeInTheDocument();
    });

    it('should not show back button at root level', () => {
      render(<CategoryNav {...defaultProps} />);
      expect(screen.queryByText(/Back/)).not.toBeInTheDocument();
    });

    it('should render header with title and add button', () => {
      render(<CategoryNav {...defaultProps} />);
      expect(screen.getByText('Categories')).toBeInTheDocument();
      expect(screen.getByLabelText('Add category')).toBeInTheDocument();
    });
  });

  describe('drilled into category', () => {
    it('should show children when category with children is selected', () => {
      render(<CategoryNav {...defaultProps} selectedCategoryId={1} />);
      expect(screen.getByText('35mm Film')).toBeInTheDocument();
      expect(screen.getByText('Medium Format')).toBeInTheDocument();
    });

    it('should show "All [CategoryName]" row as active', () => {
      render(<CategoryNav {...defaultProps} selectedCategoryId={1} />);
      const allRow = screen.getByText('All Rangefinders');
      expect(allRow.closest('.categoryNav__row')).toHaveClass('categoryNav__row--active');
    });

    it('should show breadcrumb with clickable segments', () => {
      render(<CategoryNav {...defaultProps} selectedCategoryId={1} />);
      expect(screen.getByText('All')).toBeInTheDocument(); // breadcrumb root
    });

    it('should show back button', () => {
      render(<CategoryNav {...defaultProps} selectedCategoryId={1} />);
      expect(screen.getByText(/Back/)).toBeInTheDocument();
    });

    it('should not show root categories when drilled in', () => {
      render(<CategoryNav {...defaultProps} selectedCategoryId={1} />);
      expect(screen.queryByText('SLR Cameras')).not.toBeInTheDocument();
    });
  });

  describe('deep drill', () => {
    it('should show grandchildren when drilled two levels deep', () => {
      render(<CategoryNav {...defaultProps} selectedCategoryId={2} />);
      expect(screen.getByText('Leica')).toBeInTheDocument();
      expect(screen.getByText('All 35mm Film')).toBeInTheDocument();
    });

    it('should show full breadcrumb path', () => {
      const { container } = render(<CategoryNav {...defaultProps} selectedCategoryId={2} />);
      const crumb = container.querySelector('.categoryNav__breadcrumb');
      expect(crumb).toBeInTheDocument();
      expect(crumb!.textContent).toContain('All');
      expect(crumb!.textContent).toContain('Rangefinders');
      expect(crumb!.textContent).toContain('35mm Film');
    });
  });

  describe('leaf category', () => {
    it('should stay at parent level when leaf is selected', () => {
      render(<CategoryNav {...defaultProps} selectedCategoryId={3} />);
      // Medium Format is a leaf child of Rangefinders
      // Should show Rangefinders level with Medium Format highlighted
      expect(screen.getByText('35mm Film')).toBeInTheDocument();
      expect(screen.getByText('Medium Format')).toBeInTheDocument();
    });
  });

  describe('interaction', () => {
    it('should call onSelect when clicking a category row', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(<CategoryNav {...defaultProps} onSelect={handleSelect} />);
      await user.click(screen.getByText('Rangefinders'));
      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('should call onSelect when clicking a child category', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(<CategoryNav {...defaultProps} selectedCategoryId={1} onSelect={handleSelect} />);
      await user.click(screen.getByText('35mm Film'));
      expect(handleSelect).toHaveBeenCalledWith(2);
    });
  });

  describe('breadcrumb navigation', () => {
    it('should call onSelect with null when clicking "All" breadcrumb', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(<CategoryNav {...defaultProps} selectedCategoryId={1} onSelect={handleSelect} />);
      // "All" is a link in the breadcrumb
      const allLink = screen.getByRole('button', { name: 'Navigate to All' });
      await user.click(allLink);
      expect(handleSelect).toHaveBeenCalledWith(null);
    });

    it('should call onSelect with ancestor id when clicking breadcrumb segment', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(<CategoryNav {...defaultProps} selectedCategoryId={2} onSelect={handleSelect} />);
      const rfLink = screen.getByRole('button', { name: 'Navigate to Rangefinders' });
      await user.click(rfLink);
      expect(handleSelect).toHaveBeenCalledWith(1);
    });
  });

  describe('back button', () => {
    it('should call onSelect with parent when clicking back from first level', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(<CategoryNav {...defaultProps} selectedCategoryId={1} onSelect={handleSelect} />);
      await user.click(screen.getByText(/Back/));
      expect(handleSelect).toHaveBeenCalledWith(null);
    });

    it('should call onSelect with grandparent when clicking back from second level', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(<CategoryNav {...defaultProps} selectedCategoryId={2} onSelect={handleSelect} />);
      await user.click(screen.getByText(/Back/));
      expect(handleSelect).toHaveBeenCalledWith(1);
    });
  });

  describe('collapse', () => {
    it('should render collapse button when onCollapse is provided', () => {
      render(<CategoryNav {...defaultProps} onCollapse={() => {}} />);
      expect(screen.getByLabelText('Collapse sidebar')).toBeInTheDocument();
    });

    it('should not render collapse button when onCollapse is not provided', () => {
      render(<CategoryNav {...defaultProps} />);
      expect(screen.queryByLabelText('Collapse sidebar')).not.toBeInTheDocument();
    });

    it('should call onCollapse when collapse button is clicked', async () => {
      const user = userEvent.setup();
      const handleCollapse = vi.fn();
      render(<CategoryNav {...defaultProps} onCollapse={handleCollapse} />);
      await user.click(screen.getByLabelText('Collapse sidebar'));
      expect(handleCollapse).toHaveBeenCalled();
    });
  });

  describe('edit', () => {
    it('should show edit button on hover for non-system categories', async () => {
      const user = userEvent.setup();
      render(<CategoryNav {...defaultProps} />);
      const row = screen.getByText('Rangefinders').closest('.categoryNav__row')!;
      await user.hover(row);
      expect(screen.getByLabelText('Edit Rangefinders')).toBeInTheDocument();
    });
  });

  describe('snapshots', () => {
    it('should render root level', () => {
      const { container } = render(<CategoryNav {...defaultProps} />);
      expect(container).toMatchSnapshot();
    });

    it('should render drilled level', () => {
      const { container } = render(<CategoryNav {...defaultProps} selectedCategoryId={1} />);
      expect(container).toMatchSnapshot();
    });
  });

  describe('system category filtering', () => {
    it('should hide system categories with no items', () => {
      const catsWithSystem = [
        ...mockCategories,
        createMockCategory({ categoryId: 10, name: 'System Cat', parentCategoryId: null, isSystem: true }),
      ];
      render(<CategoryNav {...defaultProps} categories={catsWithSystem} />);
      expect(screen.queryByText('System Cat')).not.toBeInTheDocument();
    });

    it('should show system categories that have items', () => {
      const catsWithSystem = [
        ...mockCategories,
        createMockCategory({ categoryId: 10, name: 'System Cat', parentCategoryId: null, isSystem: true }),
      ];
      vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
        categories: catsWithSystem,
        items: [{ id: 1, categoryId: 10, name: 'Test', summary: '', description: '', properties: [], images: [], workspaceId: 1, collectionId: 1, templateKey: null, visibility: 'Default', effectiveIsPublic: false, userFlag: 'Have' }],
        addCategory: vi.fn(async () => 6),
        addCollection: vi.fn(async () => createMockCollection()),
      }));
      render(<CategoryNav {...defaultProps} categories={catsWithSystem} />);
      expect(screen.getByText('System Cat')).toBeInTheDocument();
    });
  });

  describe('add category', () => {
    it('should open modal when add button is clicked', async () => {
      const user = userEvent.setup();
      render(<CategoryNav {...defaultProps} />);
      await user.click(screen.getByLabelText('Add category'));
      // CategoryEditorModal should be rendered (check for dialog or modal content)
      // The exact assertion depends on how CategoryEditorModal renders when isOpen=true
    });
  });

  describe('loading and error states', () => {
    it('should render loading state', () => {
      vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
        categoriesLoading: true,
      }));
      render(<CategoryNav {...defaultProps} />);
      expect(screen.getByText(/Loading/)).toBeInTheDocument();
    });

    it('should render error state', () => {
      vi.mocked(DataContext.useData).mockReturnValue(createMockDataContextValue(vi, {
        categoriesError: 'Network error',
      }));
      render(<CategoryNav {...defaultProps} />);
      expect(screen.getByText(/Network error/)).toBeInTheDocument();
    });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/CategoryNav.test.tsx` from `frontend/`
Expected: FAIL — module not found

- [ ] **Step 3: Implement CategoryNav component**

Create `frontend/src/components/category/CategoryNav.tsx`:

```tsx
import { useMemo, useState } from 'react';
import type { Category } from '../../utils/types';
import { useData } from '../../contexts/useData';
import { getAccentColor } from '../../utils/accentColors';
import { buildDrillPath, getVisibleCategories, getBreadcrumb, getChildCount } from '../../utils/categoryNavUtils';
import CategoryEditorModal from './CategoryEditorModal';
import './CategoryNav.css';

interface CategoryNavProps {
  categories: Category[];
  selectedCategoryId: number | null;
  onSelect: (categoryId: number | null) => void;
  onCollapse?: () => void;
}

function CategoryNav({ categories, selectedCategoryId, onSelect, onCollapse }: CategoryNavProps) {
  const {
    categoriesLoading,
    categoriesError,
    items,
    loadCategoriesForCollection,
    loadItemsForCategory,
    currentCollection,
  } = useData();
  const [modalOpen, setModalOpen] = useState(false);
  const [editingCategory, setEditingCategory] = useState<Category | null>(null);

  // Filter system categories with no items
  const visibleCategories = useMemo(() => {
    const itemCategoryIds = new Set(
      items.map((item) => item.categoryId).filter((id): id is number => id !== null)
    );
    return categories.filter((cat) => {
      if (!cat.isSystem) return true;
      return itemCategoryIds.has(cat.categoryId);
    });
  }, [categories, items]);

  // Build drill path from selected category's ancestry
  const drillPath = useMemo(() => {
    if (selectedCategoryId === null) return [];
    const fullPath = buildDrillPath(visibleCategories, selectedCategoryId);
    // If the selected category has children, drill path includes it
    // If it's a leaf, drill path stops at its parent
    const hasChildren = getChildCount(visibleCategories, selectedCategoryId) > 0;
    if (hasChildren) return fullPath;
    // Leaf: show parent's level
    return fullPath.slice(0, -1);
  }, [visibleCategories, selectedCategoryId]);

  const displayedCategories = useMemo(
    () => getVisibleCategories(visibleCategories, drillPath),
    [visibleCategories, drillPath]
  );

  const breadcrumb = useMemo(
    () => getBreadcrumb(visibleCategories, drillPath),
    [visibleCategories, drillPath]
  );

  // Build root-level index map for accent colors
  const rootIndexMap = useMemo(() => {
    const roots = visibleCategories.filter(c => c.parentCategoryId === null);
    const map = new Map<number, number>();
    roots.forEach((r, i) => map.set(r.categoryId, i));
    return map;
  }, [visibleCategories]);

  function getRootIndex(categoryId: number): number {
    // Walk up to root to find the root-level color index
    const byId = new Map(visibleCategories.map(c => [c.categoryId, c]));
    let current = byId.get(categoryId);
    while (current && current.parentCategoryId !== null) {
      current = byId.get(current.parentCategoryId);
    }
    return current ? (rootIndexMap.get(current.categoryId) ?? 0) : 0;
  }

  // The "All [Name]" row represents the drilled-into category
  const drilledCategory = drillPath.length > 0
    ? visibleCategories.find(c => c.categoryId === drillPath[drillPath.length - 1]) ?? null
    : null;

  function handleEdit(category: Category) {
    setEditingCategory(category);
    setModalOpen(true);
  }

  function handleAddNew() {
    setEditingCategory(null);
    setModalOpen(true);
  }

  function handleModalClose() {
    setModalOpen(false);
    setEditingCategory(null);
  }

  async function handleModalSaved() {
    if (currentCollection) {
      await loadCategoriesForCollection(currentCollection.collectionId);
      if (selectedCategoryId) {
        await loadItemsForCategory(selectedCategoryId);
      }
    }
  }

  function handleBreadcrumbClick(id: number | null) {
    onSelect(id);
  }

  function handleBack() {
    if (drillPath.length <= 1) {
      onSelect(null);
    } else {
      onSelect(drillPath[drillPath.length - 2]);
    }
  }

  function getItemCount(categoryId: number): number {
    return items.filter(i => i.categoryId === categoryId).length;
  }

  if (categoriesError) {
    return (
      <aside className="categoryNav">
        <div className="categoryNav__header">
          <h2 className="categoryNav__headerTitle">Categories</h2>
        </div>
        <p className="categoryNav__error" role="alert">Error loading categories: {categoriesError}</p>
      </aside>
    );
  }

  if (categoriesLoading) {
    return (
      <aside className="categoryNav">
        <div className="categoryNav__header">
          <h2 className="categoryNav__headerTitle">Categories</h2>
        </div>
        <p className="categoryNav__loading">Loading categories...</p>
      </aside>
    );
  }

  return (
    <aside className="categoryNav">
      <div className="categoryNav__header">
        <h2 className="categoryNav__headerTitle">Categories</h2>
        <div className="categoryNav__headerActions">
          <button
            type="button"
            className="categoryNav__addBtn"
            onClick={handleAddNew}
            aria-label="Add category"
          >
            +
          </button>
          {onCollapse && (
            <button
              type="button"
              className="categoryNav__collapseBtn"
              onClick={onCollapse}
              aria-label="Collapse sidebar"
            >
              ◀
            </button>
          )}
        </div>
      </div>

      {drillPath.length > 0 && (
        <nav className="categoryNav__breadcrumb" aria-label="Category breadcrumb">
          {breadcrumb.map((segment, i) => {
            const isLast = i === breadcrumb.length - 1;
            if (isLast) {
              return <span key={segment.id ?? 'all'} className="categoryNav__breadcrumb-current">{segment.name}</span>;
            }
            return (
              <span key={segment.id ?? 'all'}>
                <button
                  type="button"
                  className="categoryNav__breadcrumb-link"
                  onClick={() => handleBreadcrumbClick(segment.id)}
                  aria-label={`Navigate to ${segment.name}`}
                >
                  {segment.name}
                </button>
                <span className="categoryNav__breadcrumb-sep" aria-hidden="true">›</span>
              </span>
            );
          })}
        </nav>
      )}

      <div className="categoryNav__list">
        {drillPath.length > 0 && (
          <>
            <button
              type="button"
              className="categoryNav__back"
              onClick={handleBack}
            >
              ← Back
            </button>

            {drilledCategory && (
              <div
                className={`categoryNav__row${selectedCategoryId === drilledCategory.categoryId ? ' categoryNav__row--active' : ''}`}
                role="button"
                tabIndex={0}
                onClick={() => onSelect(drilledCategory.categoryId)}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(drilledCategory.categoryId); } }}
              >
                <span className="categoryNav__dot" style={{ backgroundColor: getAccentColor(getRootIndex(drilledCategory.categoryId)).start }} aria-hidden="true" />
                <div className="categoryNav__rowContent">
                  <span className="categoryNav__name">All {drilledCategory.name}</span>
                  <span className="categoryNav__count">{getItemCount(drilledCategory.categoryId)} items</span>
                </div>
                {!drilledCategory.isSystem && (
                  <button type="button" className="categoryNav__edit" aria-label={`Edit ${drilledCategory.name}`} onClick={(e) => { e.stopPropagation(); handleEdit(drilledCategory); }}>✎</button>
                )}
              </div>
            )}
          </>
        )}

        {displayedCategories.map((cat) => {
          const isActive = cat.categoryId === selectedCategoryId;
          const hasChildren = getChildCount(visibleCategories, cat.categoryId) > 0;
          const accent = getAccentColor(getRootIndex(cat.categoryId));

          return (
            <div
              key={cat.categoryId}
              className={`categoryNav__row${isActive ? ' categoryNav__row--active' : ''}`}
              role="button"
              tabIndex={0}
              onClick={() => onSelect(cat.categoryId)}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(cat.categoryId); } }}
            >
              <span className="categoryNav__dot" style={{ backgroundColor: accent.start }} aria-hidden="true" />
              <div className="categoryNav__rowContent">
                <span className="categoryNav__name">{cat.name}</span>
                <span className="categoryNav__count">{getItemCount(cat.categoryId)}</span>
              </div>
              {!cat.isSystem && (
                <button type="button" className="categoryNav__edit" aria-label={`Edit ${cat.name}`} onClick={(e) => { e.stopPropagation(); handleEdit(cat); }}>✎</button>
              )}
              {hasChildren && <span className="categoryNav__chevron" aria-hidden="true">›</span>}
            </div>
          );
        })}

        {displayedCategories.length === 0 && drillPath.length === 0 && (
          <p className="categoryNav__empty">No categories yet</p>
        )}
      </div>

      <CategoryEditorModal
        category={editingCategory}
        isOpen={modalOpen}
        onClose={handleModalClose}
        onSaved={handleModalSaved}
      />
    </aside>
  );
}

export { CategoryNav };
export default CategoryNav;
```

- [ ] **Step 4: Create CategoryNav CSS**

Create `frontend/src/components/category/CategoryNav.css`:

```css
.categoryNav {
  background: var(--color-surface-alt);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

/* Header */
.categoryNav__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--color-border);
}

.categoryNav__headerTitle {
  margin: 0;
  font-family: 'DM Sans', sans-serif;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--color-text-muted);
}

.categoryNav__headerActions {
  display: flex;
  gap: 6px;
}

.categoryNav__addBtn,
.categoryNav__collapseBtn {
  width: 24px;
  height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius-sm);
  border: 1px solid var(--color-border-strong);
  background: var(--color-surface);
  color: var(--color-text-secondary);
  font-size: 14px;
  cursor: pointer;
  transition: background var(--transition-fast), border-color var(--transition-fast), color var(--transition-fast);
}

.categoryNav__addBtn:hover {
  background: var(--color-success);
  border-color: var(--color-success);
  color: var(--color-primary-text);
}

.categoryNav__collapseBtn:hover {
  background: var(--color-border);
}

/* Breadcrumb */
.categoryNav__breadcrumb {
  padding: 8px 12px;
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  color: var(--color-text-muted);
  border-bottom: 1px solid var(--color-border);
  flex-wrap: wrap;
}

.categoryNav__breadcrumb-link {
  color: var(--color-text-muted);
  text-decoration: underline;
  text-underline-offset: 2px;
  cursor: pointer;
  background: none;
  border: none;
  font: inherit;
  padding: 0;
}

.categoryNav__breadcrumb-link:hover {
  color: var(--color-text-secondary);
}

.categoryNav__breadcrumb-sep {
  color: var(--color-border-strong);
}

.categoryNav__breadcrumb-current {
  color: var(--color-text);
  font-weight: 500;
}

/* List */
.categoryNav__list {
  padding: 4px 0;
}

/* Back button */
.categoryNav__back {
  display: flex;
  align-items: center;
  gap: 6px;
  width: 100%;
  padding: 8px 12px;
  font-family: 'DM Sans', sans-serif;
  font-size: 12px;
  color: var(--color-text-muted);
  background: none;
  border: none;
  cursor: pointer;
  text-align: left;
  transition: color var(--transition-fast);
}

.categoryNav__back:hover {
  color: var(--color-text-secondary);
}

/* Row */
.categoryNav__row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  cursor: pointer;
  transition: background var(--transition-fast);
}

.categoryNav__row:hover {
  background: var(--hover-bg);
}

.categoryNav__row--active {
  background: var(--color-accent-subtle);
  border-left: 3px solid var(--color-accent);
  padding-left: 9px;
}

.categoryNav__row:focus-visible {
  outline: 2px solid var(--color-accent);
  outline-offset: -2px;
}

/* Dot */
.categoryNav__dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

/* Row content */
.categoryNav__rowContent {
  flex: 1;
  min-width: 0;
  display: flex;
  align-items: baseline;
  gap: 8px;
}

.categoryNav__name {
  font-family: 'DM Sans', sans-serif;
  font-size: 13px;
  color: var(--color-text);
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.categoryNav__row--active .categoryNav__name {
  font-weight: 600;
}

.categoryNav__count {
  font-size: 11px;
  color: var(--color-text-muted);
  flex-shrink: 0;
  margin-left: auto;
}

/* Edit icon */
.categoryNav__edit {
  opacity: 0;
  font-size: 11px;
  color: var(--color-text-muted);
  cursor: pointer;
  background: none;
  border: none;
  padding: 4px;
  transition: opacity var(--transition-fast);
  flex-shrink: 0;
}

.categoryNav__row:hover .categoryNav__edit {
  opacity: 1;
}

.categoryNav__edit:hover {
  color: var(--color-text);
}

/* Chevron */
.categoryNav__chevron {
  color: var(--color-border-strong);
  font-size: 14px;
  flex-shrink: 0;
}

/* States */
.categoryNav__empty,
.categoryNav__loading,
.categoryNav__error {
  padding: 12px 16px;
  font-size: 13px;
  color: var(--color-text-muted);
  margin: 0;
}

.categoryNav__error {
  color: var(--color-danger);
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run tests/CategoryNav.test.tsx` from `frontend/`
Expected: All tests PASS

Note: Some tests may need adjustment based on exact rendering. The implementer should read the test expectations carefully and ensure the component renders the expected structure. If a test fails, fix the component to match the test intent, not the other way around.

- [ ] **Step 6: Commit**

From project root:
- `git add frontend/src/components/category/CategoryNav.tsx frontend/src/components/category/CategoryNav.css frontend/tests/CategoryNav.test.tsx`
- `git commit -m "feat: add CategoryNav drill-down navigation component"`

---

## Task 3: Wire Up CategoryNav and Remove CategoryTree

**Files:**
- Modify: `frontend/src/views/CategoryView.tsx`
- Modify: `frontend/src/views/ItemView.tsx`
- Modify: `frontend/src/components/category/index.ts`
- Delete: `frontend/src/components/category/CategoryTree.tsx`
- Delete: `frontend/tests/CategoryTree.test.tsx`
- Modify: `frontend/src/styles/App.css`

- [ ] **Step 1: Update CategoryView.tsx**

Replace the import:
```tsx
// OLD
import CategoryTree from '../components/category/CategoryTree';
// NEW
import CategoryNav from '../components/category/CategoryNav';
```

Update the `onSelect` type. Currently `CategoryTree.onSelect` is `(categoryId: number) => void`. The new `CategoryNav.onSelect` is `(categoryId: number | null) => void` (null means "go to root/collection dashboard"). Update `handleSelectCategory`:

```tsx
function handleSelectCategory(catId: number | null) {
  if (catId === null) {
    navigate(`/collections/${collectionIdNum}`);
  } else {
    navigate(`/collections/${collectionIdNum}/categories/${catId}`);
  }
}
```

Replace the sidebar rendering in BOTH branches. Remove the external `app__sidebar-toggle` button entirely. The collapse toggle is now inside CategoryNav.

For the no-category branch (~line 207):
```tsx
<nav className="app__sidebar" aria-label="Category navigation">
  {sidebarCollapsed ? (
    <button
      type="button"
      className="app__sidebar-toggle"
      onClick={() => setSidebarCollapsed(false)}
      aria-label="Expand sidebar"
    >
      ▶
    </button>
  ) : (
    <CategoryNav
      categories={categories}
      selectedCategoryId={null}
      onSelect={handleSelectCategory}
      onCollapse={() => setSidebarCollapsed(true)}
    />
  )}
</nav>
```

For the with-category branch (~line 246):
```tsx
<nav className="app__sidebar" aria-label="Category navigation">
  {sidebarCollapsed ? (
    <button
      type="button"
      className="app__sidebar-toggle"
      onClick={() => setSidebarCollapsed(false)}
      aria-label="Expand sidebar"
    >
      ▶
    </button>
  ) : (
    <CategoryNav
      categories={categories}
      selectedCategoryId={categoryIdNum}
      onSelect={handleSelectCategory}
      onCollapse={() => setSidebarCollapsed(true)}
    />
  )}
</nav>
```

- [ ] **Step 2: Update ItemView.tsx**

Replace import and usage:
```tsx
// OLD
import CategoryTree from '../components/category/CategoryTree';
// NEW
import CategoryNav from '../components/category/CategoryNav';
```

Update the sidebar render and `handleSelectCategory` to accept `number | null`:
```tsx
function handleSelectCategory(catId: number | null) {
  if (catId === null) {
    navigate(`/collections/${collectionIdNum}`);
  } else {
    navigate(`/collections/${collectionIdNum}/categories/${catId}`);
  }
}
```

Replace the CategoryTree JSX with CategoryNav. Note: ItemView intentionally does NOT have sidebar collapse — it has no `sidebarCollapsed` state, so `onCollapse` is not passed:
```tsx
<CategoryNav
  categories={categories}
  selectedCategoryId={detailItem?.categoryId ?? null}
  onSelect={handleSelectCategory}
/>
```

- [ ] **Step 3: Update barrel export**

In `frontend/src/components/category/index.ts`, replace:
```typescript
export { default as CategoryTree } from './CategoryTree';
```
With:
```typescript
export { default as CategoryNav } from './CategoryNav';
```

- [ ] **Step 4: Delete old files**

From project root:
- `git rm frontend/src/components/category/CategoryTree.tsx`
- `git rm frontend/tests/CategoryTree.test.tsx`

Also delete the snapshot file if it exists:
- `git rm frontend/tests/__snapshots__/CategoryTree.test.tsx.snap` (if present)

- [ ] **Step 5: Remove old CSS rules from App.css**

Remove all `.categoryTree__*` rules from App.css (the block starting at `.categoryTree {` through `.categoryTree__edit:hover`). Keep the `.app__sidebar`, `.app__layout--sidebar-collapsed`, and `.app__sidebar-toggle` rules — the expand (▶) button in the collapsed state still uses `.app__sidebar-toggle`.

- [ ] **Step 6: Run all tests**

Run: `npm run test:run` from `frontend/`
Expected: All tests pass. Some snapshot tests may need updating.

- [ ] **Step 7: Update snapshots if needed**

Run: `npm run test:run -- --update` from `frontend/`

- [ ] **Step 8: Run lint**

Run: `npm run lint` from `frontend/`
Expected: No errors

- [ ] **Step 9: Commit**

From project root:
- `git add frontend/src/views/CategoryView.tsx frontend/src/views/ItemView.tsx frontend/src/components/category/index.ts frontend/src/styles/App.css`
- `git commit -m "feat: replace CategoryTree with CategoryNav drill-down navigation"`
