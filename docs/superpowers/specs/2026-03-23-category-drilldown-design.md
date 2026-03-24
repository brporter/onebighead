# Category Drill-Down Navigation — Design Spec

**Date:** 2026-03-23
**Status:** Draft
**Scope:** Replace the category tree sidebar with drill-down navigation

## Problem

The current category tree has layout issues: the collapse toggle floats above the tree disconnected from it, and nested categories cause text wrapping because indentation consumes too much horizontal space. Deeper nesting makes the problem worse — each level adds 22px of left padding, leaving progressively less room for category names.

More fundamentally, the indented tree pattern is a poor fit for a narrow sidebar. Every level of nesting compresses the available space for the content that matters (the category name).

## Solution: Drill-Down Navigation

Replace the hierarchical tree with a single-level list that navigates into children on click. Only one level of the hierarchy is visible at a time, with a breadcrumb trail showing the current path and enabling fast jumps to any ancestor level.

### Core Principles

1. **Every category gets the full sidebar width.** No indentation, no truncation.
2. **Drill in = select.** Clicking a category with children both selects it (loading its items) and reveals its children in the sidebar.
3. **Breadcrumbs enable fast jumps.** Clicking any breadcrumb segment navigates directly to that level — no repeated back-clicks.
4. **Leaf categories just select.** Categories without children are simple select actions with no drill.

## 1. Component Structure

### Sidebar States

The sidebar shows one of these states at any time:

**Root level** (no category selected):
```
┌─────────────────────────────┐
│ CATEGORIES          [+] [◀] │
├─────────────────────────────┤
│ ● Rangefinders         12 › │
│ ● SLR Cameras          18 › │
│ ● Twin-Lens Reflex      6   │
│ ● Compact & P&S         8   │
│ ● Accessories            3   │
└─────────────────────────────┘
```

**Drilled into a category** (category selected, has children):
```
┌─────────────────────────────┐
│ CATEGORIES          [+] [◀] │
├─────────────────────────────┤
│ All › Rangefinders          │
├─────────────────────────────┤
│ ← Back                      │
│ ● All Rangefinders     12 ✎ │  ← active/selected
│ ● 35mm Film             8 › │
│ ● Medium Format         4   │
└─────────────────────────────┘
```

**Drilled into a leaf category** (category selected, no children):
```
┌─────────────────────────────┐
│ CATEGORIES          [+] [◀] │
├─────────────────────────────┤
│ All › Rangefinders › 35mm   │
├─────────────────────────────┤
│ ← Back                      │
│ ● 35mm Film             8 ✎ │  ← active/selected
└─────────────────────────────┘
```

### Visual Elements Per Row

Each category row contains:
- **Accent dot** (8px circle, category color from palette)
- **Category name** (DM Sans, 13px, full width)
- **Item count** (right-aligned, muted)
- **Edit icon** (✎, visible on hover, non-system categories only)
- **Chevron** (›, only on categories that have children — indicates "drill deeper")

### Header

The header contains:
- "CATEGORIES" label (uppercase, tracked, DM Sans 11px)
- Add category button (+)
- Collapse sidebar button (◀)

The collapse button is part of the CategoryTree component header, not a separate floating element in the sidebar.

### Breadcrumb Bar

Shown when drilled into any category (not at root level):
- Each segment is clickable — navigates to that level
- Current (deepest) segment is non-clickable, bold
- Separator: `›`
- Font: DM Sans 11px, muted color for links, text color for current
- Sits between the header and the category list, separated by borders

### Back Row

Shown when not at root level:
- "← Back" text
- Navigates up one level (to parent category, or root if at first level)
- Muted color, darker on hover

## 2. Interaction Model

### Clicking a Category Row

**If category has children:**
1. Select the category (update URL, load items in main content)
2. Drill the sidebar into that category — show its children as a flat list
3. Show "All [CategoryName]" as the first row (active/selected)
4. Show child categories below with their own chevrons (if they have children)

**If category has no children (leaf):**
1. Select the category (update URL, load items)
2. Sidebar stays at current drill level — the clicked row becomes active
3. No drill deeper

### Clicking Breadcrumb Segments

- Clicking a breadcrumb navigates directly to that category's level
- This both selects that category AND shows its children
- Clicking "All" (root breadcrumb) navigates to the collection dashboard (no category selected)

### Clicking Back

- Navigates up one level to the parent category
- Selects the parent and shows its siblings
- At the first drill level, "Back" returns to root (collection dashboard)

### Clicking the "All [CategoryName]" Row

- This row is auto-selected when drilling in
- Clicking it again is a no-op (already selected)
- It shows all items in the parent + descendants (same as current behavior)

### Edit Icon

- Visible on hover for non-system categories
- Opens CategoryEditorModal (same as current behavior)
- Available on all rows including "All [CategoryName]"

## 3. Styling

### Category Row

```css
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
  padding-left: 9px; /* compensate for border */
}
```

### Breadcrumb

```css
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

.categoryNav__breadcrumb a {
  color: var(--color-text-muted);
  text-decoration: underline;
  text-underline-offset: 2px;
  cursor: pointer;
}

.categoryNav__breadcrumb a:hover {
  color: var(--color-text-secondary);
}

.categoryNav__breadcrumb-current {
  color: var(--color-text);
  font-weight: 500;
}
```

### Chevron

```css
.categoryNav__chevron {
  color: var(--color-border-strong);
  font-size: 14px;
  flex-shrink: 0;
}
```

### Row Content

```css
.categoryNav__name {
  font-family: 'DM Sans', sans-serif;
  font-size: 13px;
  color: var(--color-text);
  font-weight: 500;
}

.categoryNav__count {
  font-size: 11px;
  color: var(--color-text-muted);
  margin-left: auto;
}

.categoryNav__edit {
  opacity: 0;
  font-size: 11px;
  color: var(--color-text-muted);
  cursor: pointer;
  transition: opacity var(--transition-fast);
  background: none;
  border: none;
  padding: 4px;
}

.categoryNav__row:hover .categoryNav__edit {
  opacity: 1;
}
```

### Transition

When drilling in or out, the list content slides horizontally:
- Drill in: content slides left (new level enters from right)
- Back/breadcrumb up: content slides right (parent level enters from left)
- Duration: `0.2s ease`
- Respects `prefers-reduced-motion`

## 4. State Management

### New State

The drill-down requires tracking the "drill path" — the chain of categories from root to the current drill level. This replaces `expandedCategoryIds`.

```typescript
// In DataContext or CategoryTree local state:
const [drillPath, setDrillPath] = useState<number[]>([]);
// drillPath = [] means root level
// drillPath = [5] means drilled into category 5
// drillPath = [5, 12] means drilled into category 5's child 12
```

### Deriving Visible Categories

```typescript
function getVisibleCategories(categories: Category[], drillPath: number[]): Category[] {
  if (drillPath.length === 0) {
    // Root level: show top-level categories (parentCategoryId === null)
    return categories.filter(c => c.parentCategoryId === null);
  }
  // Drilled level: show children of the last category in the path
  const currentId = drillPath[drillPath.length - 1];
  return categories.filter(c => c.parentCategoryId === currentId);
}
```

### Deriving Breadcrumb

```typescript
function getBreadcrumb(categories: Category[], drillPath: number[]): { id: number | null; name: string }[] {
  const crumbs = [{ id: null, name: 'All' }];
  for (const catId of drillPath) {
    const cat = categories.find(c => c.categoryId === catId);
    if (cat) crumbs.push({ id: cat.categoryId, name: cat.name });
  }
  return crumbs;
}
```

### Integration with URL Routing

The current app navigates to `/collections/{id}/categories/{categoryId}` when a category is selected. The drill-down should derive its drill path from the selected category's ancestry:

```typescript
// On category selection (from URL), build drill path from category's ancestors
function buildDrillPathForCategory(categories: Category[], categoryId: number): number[] {
  const path: number[] = [];
  let current = categories.find(c => c.categoryId === categoryId);
  while (current) {
    path.unshift(current.categoryId);
    current = current.parentCategoryId
      ? categories.find(c => c.categoryId === current!.parentCategoryId)
      : undefined;
  }
  return path;
}
```

This ensures deep links work: navigating directly to a deeply nested category builds the correct drill path.

## 5. Sidebar Collapse Integration

The collapse button (◀) lives in the CategoryTree/CategoryNav header. When collapsed:
- The sidebar shrinks to 48px
- Only the expand button (▶) is shown
- No category content is visible

This is the same behavior as currently specified, but the toggle is now inside the component instead of floating above it.

## 6. Scope

### In Scope
- New `CategoryNav` component replacing `CategoryTree` for drill-down
- Breadcrumb navigation with clickable segments
- Back button navigation
- Slide transition animation on drill in/out
- Collapse button integrated into component header
- Edit icon on hover (existing CategoryEditorModal)
- Add category button (existing functionality)
- Deep link support (URL → drill path derivation)
- Accent color dots per category (existing palette)
- Item counts per category row

### Out of Scope
- Drag-and-drop reordering of categories
- Search/filter within the category list
- Keyboard arrow-key navigation between rows
- Persisting drill state to localStorage

## 7. Component Rename

The component is renamed from `CategoryTree` to `CategoryNav` to reflect the new interaction pattern. CSS classes change from `categoryTree__*` to `categoryNav__*`. The old component and its CSS are removed entirely.
