# Category Manager Design

## Problem

The CategoryNav sidebar currently mixes navigation and editing concerns. Inline controls — add, edit, publish, unpublish — consume space needed for category labels and clutter the visual design. The more categories a collection has, the worse this gets.

## Solution

Extract all category editing into a dedicated **Category Manager** modal. The CategoryNav becomes a clean, read-only navigation component. The Category Manager provides a two-panel layout: a tree browser on the left and an edit form on the right. A new sort order feature enables drag-and-drop reordering and alphabetical sorting.

## Entry Points

1. **CategoryNav header** — the current `+` (add) button is replaced with an Edit button (pencil icon) that opens the Category Manager, scoped to the current collection.
2. **SettingsView collection cards** — a new "Categories" button alongside the existing "Templates" and "Edit" buttons, opening the same modal for that collection.

## CategoryNav Changes

The following inline controls are removed from CategoryNav:
- `+` (add) button in the header
- Publish button on each row (hidden-on-hover)
- Public badge on each row
- Edit (pencil) button on each row

What remains (read-only):
- Category names with accent color dots
- Chevrons indicating child categories
- Drill-down navigation, breadcrumbs, and back button
- Collapse/expand sidebar toggle
- Active row highlighting

A new Edit button is added to the header actions area, replacing the add button.

## Category Manager Modal

### Layout

Side-by-side panels inside a wide modal (~800px+):
- **Left panel (~280px)**: Full category tree with toolbar
- **Right panel (flex)**: Edit form for the selected category

### Left Panel — Tree

Renders the full hierarchy with:
- Indented rows showing category name, accent color dot, and chevron for parents
- Active/selected row highlighting matching the existing CategoryNav style
- Drag handle (grip dots) on hover at the left edge of each row
- `@dnd-kit/sortable` for drag-and-drop (see Drag-and-Drop section)

**Toolbar** at the top of the tree panel:
- "Categories" label (matching existing CategoryNav header style)
- Add (+) button — creates a new category, defaulting parent to the currently selected category (or root if nothing selected)
- Sort Alphabetically (A↓) button — opens the SortConfirmModal

### Right Panel — Edit Form

When a category is selected, the form shows:
- **Header**: Category name and public status badge
- **Name** (required, validated: non-empty, "Unassigned Items" reserved)
- **Description** (optional textarea)
- **Parent Category** (dropdown, excludes self and descendants to prevent circular references)
- **Recommended Templates** (template selector, same as current CategoryEditorModal)
- **Visibility**: Publish/Unpublish button with status text

**Footer**:
- Left: Delete Category button (danger style)
- Right: Cancel and Save Changes buttons

**Empty state** (no category selected): "Select a category to edit, or click + to add a new one."

**System categories**: Form fields are disabled with a message: "System categories cannot be modified."

## Drag-and-Drop

Uses `@dnd-kit` (already a project dependency) for both reordering and reparenting.

### Reorder (within siblings)
- Drag a category up/down within its sibling group to change sort order.
- On drop, recompute `SortOrder` values for the affected sibling group and call the reorder endpoint.

### Reparent (move to different parent)
- Drag a category onto another category (visual highlight on the drop target) to make it a child of that category.
- The dropped category is appended to the end of the new parent's children.
- Dragging to a dedicated "root level" drop zone at the top or bottom of the tree removes the parent (makes it a root category).
- **Validation**: Dropping a category onto itself or any of its own descendants is prevented (would create a circular reference). The drop target shows a "not allowed" indicator.
- After reparent: the edit form's Parent Category dropdown updates to reflect the new parent. A save is triggered automatically for the parent change, plus a reorder call for the new sibling group.

The edit form's Parent Category dropdown remains as a fallback for users who prefer explicit selection over dragging.

## Sort Alphabetically

The Sort Alphabetically button in the tree toolbar opens a `SortConfirmModal` with:
- **"This level only"**: Sorts the siblings of the selected category (i.e., categories sharing the same parent). If nothing is selected, sorts root-level categories.
- **"All levels"**: Recursively sorts every level of the hierarchy.
- Warning text that this will overwrite any custom ordering.
- Cancel button to abort.

On confirm, sort orders are recomputed client-side and sent as a bulk reorder request.

## Backend Changes

### Category Model
Add `SortOrder` (int) property to the `Category` entity.

### Migration
- Add `SortOrder` column to the Categories table.
- Seed default values: assign alphabetical order by name within each parent group (root categories get 0, 1, 2... alphabetically; children within each parent get 0, 1, 2... alphabetically).

### API Endpoint
New endpoint: `PUT /api/categories/reorder`
- Request body: array of `{ categoryId: int, sortOrder: int }`
- Validates all category IDs belong to the same collection and workspace
- Accepts categories across different parents (needed for "All levels" alphabetical sort)
- Bulk updates sort order values
- Returns updated categories

### Query Ordering
All category queries return results ordered by `SortOrder` ascending, then `Name` ascending as tiebreaker.

## Component Architecture

### New Components
- **`CategoryManagerModal`** — top-level modal shell. Props: `collectionId`, `isOpen`, `onClose`. Owns selected category state, manages load/save lifecycle.
- **`CategoryManagerTree`** — left panel. Renders indented tree with `@dnd-kit` drag-and-drop. Emits `onSelect`, `onReorder`, `onReparent`. Contains toolbar (Add, Sort Alphabetically).
- **`CategoryManagerForm`** — right panel. Edit form for selected category. Emits `onSave`, `onDelete`. Shows empty state when nothing selected.
- **`SortConfirmModal`** — nested dialog for alphabetical sort confirmation with "This level only" / "All levels" options.

### Modified Components
- **`CategoryNav`** — remove all inline edit controls, add Edit button to header.
- **`SettingsView`** — add "Categories" button to collection cards.

### Data Flow
1. `CategoryManagerModal` opens, loads categories via `DataContext.loadCategoriesForCollection()`.
2. User selects a category in the tree. `CategoryManagerForm` populates with that category's data.
3. User edits and clicks Save. Calls `DataContext.updateCategory()`. Tree refreshes from local state.
4. User drags to reorder. Calls new `DataContext.reorderCategories()` for bulk sort order update.
5. User drags to reparent. Calls `DataContext.updateCategory()` with new `parentCategoryId`, then `reorderCategories()` for the new sibling group.
6. User clicks Add. Form switches to create mode with empty fields; parent defaults to currently selected category (or root).
7. User clicks Delete. Confirmation dialog, then `DataContext.deleteCategory()`. Tree refreshes, selection clears.
8. User publishes/unpublishes. Calls existing `DataContext.publishCategory()` / `unpublishCategory()`. Tree refreshes.
9. On modal close, `CategoryNav` reflects all changes (categories already updated in DataContext).

No new API modules are needed beyond the reorder endpoint. All other operations use existing `categoriesApi` methods.

## Testing Strategy

### New Unit Tests
- **`CategoryManagerModal`** — open/close lifecycle, loads categories on open, passes collection context.
- **`CategoryManagerTree`** — renders hierarchy with correct indentation, selection highlighting, drag-and-drop reorder fires `onReorder`, drag-to-reparent fires `onReparent`, prevents circular reparenting, toolbar Add button triggers callback, Sort Alphabetically button opens confirmation.
- **`CategoryManagerForm`** — renders fields for selected category, empty state when no selection, form validation (name required, reserved name check), Save/Cancel/Delete callbacks, publish/unpublish actions, disabled state for system categories.
- **`SortConfirmModal`** — renders both options, fires correct callback for each, cancel closes without action.

### Existing Test Updates
- **`CategoryNav.test.tsx`** — remove tests for inline edit/publish/add buttons, add test for Edit button opening the manager.
- **`CategoryView.test.tsx`** — update to reflect removed inline controls, test that Edit button in CategoryNav header opens CategoryManagerModal.
- **`SettingsView` tests** — add test for "Categories" button on collection cards.

### Backend Tests
- `SortOrder` migration applies correctly, defaults assigned.
- Reorder endpoint validates input, updates sort orders, rejects invalid category IDs.
- Categories returned in sort order.

### Coverage
100% on all new and modified code per project requirements.
