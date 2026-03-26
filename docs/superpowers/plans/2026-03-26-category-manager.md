# Category Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace inline category editing controls with a dedicated two-panel Category Manager modal, and add drag-and-drop reordering support.

**Architecture:** New `CategoryManagerModal` component with a tree panel (left) and edit form (right). Backend gets a `SortOrder` column on Category and a bulk reorder endpoint. CategoryNav becomes read-only. Entry points from CategoryNav header and SettingsView collection cards.

**Tech Stack:** React 19, @dnd-kit/core + @dnd-kit/sortable, .NET 10 / EF Core, xUnit, Vitest

**Spec:** `docs/superpowers/specs/2026-03-26-category-manager-design.md`

---

## File Structure

### New Files
| File | Responsibility |
|------|---------------|
| `backend/src/backend/DTOs/ReorderCategoriesRequest.cs` | DTO for bulk reorder endpoint |
| `backend/src/backend/Migrations/*_AddCategorySortOrder.cs` | Migration adding SortOrder column |
| `frontend/src/components/category/CategoryManagerModal.tsx` | Top-level modal shell, owns selected category state |
| `frontend/src/components/category/CategoryManagerModal.css` | Styles for modal layout (two-panel, tree, form) |
| `frontend/src/components/category/CategoryManagerTree.tsx` | Left panel: tree with dnd-kit drag-and-drop |
| `frontend/src/components/category/CategoryManagerForm.tsx` | Right panel: edit form for selected category |
| `frontend/src/components/category/SortConfirmModal.tsx` | Nested confirmation dialog for alphabetical sort |
| `frontend/tests/CategoryManagerModal.test.tsx` | Tests for modal lifecycle |
| `frontend/tests/CategoryManagerTree.test.tsx` | Tests for tree rendering, selection, DnD |
| `frontend/tests/CategoryManagerForm.test.tsx` | Tests for edit form |
| `frontend/tests/SortConfirmModal.test.tsx` | Tests for sort confirmation dialog |
| `backend/tests/backend.tests/Integration/Controllers/CategoriesControllerReorderTests.cs` | Tests for reorder endpoint |

### Modified Files
| File | Changes |
|------|---------|
| `backend/src/backend/Models/Category.cs` | Add `SortOrder` property |
| `backend/src/backend/DTOs/CategoryResponse.cs` | Add `SortOrder` to response |
| `backend/src/backend/Data/ICategoryRepository.cs` | Add `ReorderAsync` method |
| `backend/src/backend/Data/CategoryRepository.cs` | Implement `ReorderAsync`, add OrderBy to queries |
| `backend/src/backend/Controllers/CategoriesController.cs` | Add `Reorder` endpoint |
| `frontend/src/api/categories.ts` | Add `reorder` method |
| `frontend/src/utils/types.ts` | Add `sortOrder` to `Category` interface |
| `frontend/src/contexts/DataContext.tsx` | Add `reorderCategories` method |
| `frontend/src/components/category/CategoryNav.tsx` | Remove inline edit controls, add Edit button |
| `frontend/src/components/category/CategoryNav.css` | Remove edit/publish styles, add edit button style |
| `frontend/src/components/category/index.ts` | Export new components |
| `frontend/src/views/SettingsView.tsx` | Add "Categories" button to collection cards |
| `frontend/src/views/CategoryView.tsx` | Wire CategoryManagerModal to CategoryNav edit button |
| `frontend/tests/CategoryNav.test.tsx` | Update for read-only tree + edit button |
| `frontend/tests/views/CategoryView.test.tsx` | Update for CategoryManagerModal integration |

---

## Task 1: Backend — Add SortOrder to Category Model

**Files:**
- Modify: `backend/src/backend/Models/Category.cs:28` (before Visibility)
- Modify: `backend/src/backend/DTOs/CategoryResponse.cs:16` (before ItemTemplateIds)

- [ ] **Step 1: Write failing test for SortOrder on Category model**

Create a test that verifies the Category model has a SortOrder property:

```csharp
// In a new or existing test file — verify the property exists and defaults to 0
var category = new Category();
Assert.Equal(0, category.SortOrder);
```

Run: `dotnet test backend/tests/backend.tests --filter "SortOrder"`
Expected: FAIL — Category does not have SortOrder property

- [ ] **Step 2: Add SortOrder property to Category model**

In `backend/src/backend/Models/Category.cs`, add after line 26 (`ParentCategoryId`):

```csharp
public int SortOrder { get; set; } = 0;
```

- [ ] **Step 3: Add SortOrder to CategoryResponse DTO**

In `backend/src/backend/DTOs/CategoryResponse.cs`, add before `ItemTemplateIds` (line 16):

```csharp
public int SortOrder { get; set; }
```

In the `FromCategory` method, add:

```csharp
SortOrder = category.SortOrder,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test backend/tests/backend.tests --filter "SortOrder"`
Expected: PASS

- [ ] **Step 5: Create migration**

Run: `cd backend/src/backend && dotnet ef migrations add AddCategorySortOrder`

Verify the generated migration adds a `SortOrder` int column with default value 0.

- [ ] **Step 6: Add data seed in migration**

Edit the generated migration's `Up` method to seed default sort orders alphabetically within each parent group. After the `AddColumn`, add:

```csharp
// Seed default sort orders: alphabetical within each parent group
migrationBuilder.Sql(@"
    WITH Ranked AS (
        SELECT Id, ROW_NUMBER() OVER (PARTITION BY ParentCategoryId, CollectionId ORDER BY Name) - 1 AS NewSort
        FROM Categories
    )
    UPDATE c SET c.SortOrder = r.NewSort
    FROM Categories c INNER JOIN Ranked r ON c.Id = r.Id
");
```

- [ ] **Step 7: Run all backend tests**

Run: `dotnet test backend/tests/backend.tests`
Expected: All tests pass

- [ ] **Step 8: Commit**

```bash
git add backend/src/backend/Models/Category.cs backend/src/backend/DTOs/CategoryResponse.cs backend/src/backend/Migrations/
git commit -m "feat: add SortOrder property to Category model with migration"
```

---

## Task 2: Backend — Add OrderBy to Category Queries

**Files:**
- Modify: `backend/src/backend/Data/CategoryRepository.cs:15-29`

- [ ] **Step 1: Write failing test for sort order in query results**

```csharp
[Fact]
public async Task GetByCollectionAsync_ReturnsCategoriesOrderedBySortOrderThenName()
{
    var categories = new List<Category>
    {
        new() { WorkspaceId = 1, CollectionId = 1, Name = "Bravo", SortOrder = 1 },
        new() { WorkspaceId = 1, CollectionId = 1, Name = "Alpha", SortOrder = 0 },
        new() { WorkspaceId = 1, CollectionId = 1, Name = "Charlie", SortOrder = 1 },
    };
    await _context.Categories.AddRangeAsync(categories);
    await _context.SaveChangesAsync();

    var result = (await _repository.GetByCollectionAsync(1, 1)).ToList();

    Assert.Equal("Alpha", result[0].Name);
    Assert.Equal("Bravo", result[1].Name);
    Assert.Equal("Charlie", result[2].Name);
}
```

Run: `dotnet test backend/tests/backend.tests --filter "OrderedBySortOrder"`
Expected: FAIL — results are unordered

- [ ] **Step 2: Add OrderBy to GetAllAsync and GetByCollectionAsync**

In `backend/src/backend/Data/CategoryRepository.cs`, update both methods:

`GetAllAsync` (line 15-21): Add `.OrderBy(c => c.SortOrder).ThenBy(c => c.Name)` before `.ToListAsync()`.

`GetByCollectionAsync` (line 23-29): Add `.OrderBy(c => c.SortOrder).ThenBy(c => c.Name)` before `.ToListAsync()`.

- [ ] **Step 3: Run test to verify it passes**

Run: `dotnet test backend/tests/backend.tests --filter "OrderedBySortOrder"`
Expected: PASS

- [ ] **Step 4: Run all backend tests**

Run: `dotnet test backend/tests/backend.tests`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add backend/src/backend/Data/CategoryRepository.cs backend/tests/
git commit -m "feat: order categories by SortOrder then Name in queries"
```

---

## Task 3: Backend — Reorder Endpoint

**Files:**
- Create: `backend/src/backend/DTOs/ReorderCategoriesRequest.cs`
- Modify: `backend/src/backend/Data/ICategoryRepository.cs`
- Modify: `backend/src/backend/Data/CategoryRepository.cs`
- Modify: `backend/src/backend/Controllers/CategoriesController.cs`
- Create: `backend/tests/backend.tests/Integration/Controllers/CategoriesControllerReorderTests.cs`

- [ ] **Step 1: Create ReorderCategoriesRequest DTO**

Create `backend/src/backend/DTOs/ReorderCategoriesRequest.cs`:

```csharp
using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class ReorderCategoriesRequest
{
    [Required]
    public List<CategorySortOrderEntry> Categories { get; set; } = new();
}

public class CategorySortOrderEntry
{
    public int CategoryId { get; set; }
    public int SortOrder { get; set; }
}
```

- [ ] **Step 2: Write failing test for ReorderAsync repository method**

```csharp
[Fact]
public async Task ReorderAsync_UpdatesSortOrderForMultipleCategories()
{
    var cat1 = new Category { WorkspaceId = 1, CollectionId = 1, Name = "A", SortOrder = 0 };
    var cat2 = new Category { WorkspaceId = 1, CollectionId = 1, Name = "B", SortOrder = 1 };
    await _context.Categories.AddRangeAsync(cat1, cat2);
    await _context.SaveChangesAsync();

    var updates = new Dictionary<int, int> { { cat1.Id, 1 }, { cat2.Id, 0 } };
    await _repository.ReorderAsync(updates, 1);

    var result = (await _repository.GetByCollectionAsync(1, 1)).ToList();
    Assert.Equal("B", result[0].Name);
    Assert.Equal("A", result[1].Name);
}
```

Run: `dotnet test backend/tests/backend.tests --filter "ReorderAsync"`
Expected: FAIL — method does not exist

- [ ] **Step 3: Add ReorderAsync to ICategoryRepository**

In `backend/src/backend/Data/ICategoryRepository.cs`, add:

```csharp
Task ReorderAsync(Dictionary<int, int> categoryIdToSortOrder, int workspaceId);
```

- [ ] **Step 4: Implement ReorderAsync in CategoryRepository**

In `backend/src/backend/Data/CategoryRepository.cs`, add:

```csharp
public async Task ReorderAsync(Dictionary<int, int> categoryIdToSortOrder, int workspaceId)
{
    var categoryIds = categoryIdToSortOrder.Keys.ToList();
    var categories = await _context.Categories
        .Where(c => c.WorkspaceId == workspaceId && categoryIds.Contains(c.Id))
        .ToListAsync();

    foreach (var category in categories)
    {
        if (categoryIdToSortOrder.TryGetValue(category.Id, out var newSortOrder))
        {
            category.SortOrder = newSortOrder;
        }
    }

    await _context.SaveChangesAsync();
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `dotnet test backend/tests/backend.tests --filter "ReorderAsync"`
Expected: PASS

- [ ] **Step 6: Write failing test for reorder controller endpoint**

Test that `PUT /api/categories/reorder` updates sort orders and validates workspace ownership.

- [ ] **Step 7: Add Reorder endpoint to CategoriesController**

In `backend/src/backend/Controllers/CategoriesController.cs`, add:

```csharp
[HttpPut("reorder")]
public async Task<ActionResult<IEnumerable<CategoryResponse>>> ReorderCategories(ReorderCategoriesRequest request)
{
    var workspaceId = GetWorkspaceId();

    if (request.Categories.Count == 0)
    {
        return BadRequest("No categories to reorder");
    }

    // Validate all categories belong to this workspace
    var categoryIds = request.Categories.Select(c => c.CategoryId).ToList();
    var existingCategories = new List<Category>();
    foreach (var id in categoryIds)
    {
        var cat = await _categoryRepository.GetByIdAsync(id, workspaceId);
        if (cat is null)
        {
            return BadRequest($"Category {id} not found in workspace");
        }
        existingCategories.Add(cat);
    }

    // Validate all categories belong to the same collection
    var collectionIds = existingCategories.Select(c => c.CollectionId).Distinct().ToList();
    if (collectionIds.Count > 1)
    {
        return BadRequest("All categories must belong to the same collection");
    }

    var updates = request.Categories.ToDictionary(c => c.CategoryId, c => c.SortOrder);
    await _categoryRepository.ReorderAsync(updates, workspaceId);

    // Return updated category list
    var collectionId = collectionIds[0];
    var collection = await _collectionRepository.GetByIdAsync(collectionId, workspaceId);
    var allCategories = (await _categoryRepository.GetByCollectionAsync(collectionId, workspaceId)).ToList();
    if (collection != null)
    {
        _visibilityService.ComputeEffectiveVisibility(allCategories, collection);
    }
    var templateIdsByCategory = await _categoryRepository.GetTemplateIdsByCategoryAsync(collectionId, workspaceId);
    var response = allCategories.Select(c => CategoryResponse.FromCategory(
        c,
        templateIdsByCategory.TryGetValue(c.Id, out var ids) ? ids : null
    ));
    return Ok(response);
}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `dotnet test backend/tests/backend.tests --filter "Reorder"`
Expected: PASS

- [ ] **Step 9: Run all backend tests**

Run: `dotnet test backend/tests/backend.tests`
Expected: All tests pass

- [ ] **Step 10: Commit**

```bash
git add backend/src/backend/DTOs/ReorderCategoriesRequest.cs backend/src/backend/Data/ backend/src/backend/Controllers/CategoriesController.cs backend/tests/
git commit -m "feat: add bulk reorder endpoint for categories"
```

---

## Task 4: Frontend — Add sortOrder to Types and API

**Files:**
- Modify: `frontend/src/utils/types.ts:96-107`
- Modify: `frontend/src/api/categories.ts`
- Modify: `frontend/src/contexts/DataContext.tsx`

- [ ] **Step 1: Add sortOrder to Category interface**

In `frontend/src/utils/types.ts`, add after `itemTemplateIds` (line 106):

```typescript
sortOrder: number;
```

- [ ] **Step 2: Add reorder method to categories API**

In `frontend/src/api/categories.ts`, add the request interface and API method:

```typescript
export interface ReorderCategoriesRequest {
  categories: { categoryId: number; sortOrder: number }[];
}
```

Add to the `categoriesApi` object:

```typescript
reorder(request: ReorderCategoriesRequest): Promise<Category[]> {
  return api.put<Category[]>('/categories/reorder', request);
},
```

- [ ] **Step 3: Add reorderCategories to DataContext**

In `frontend/src/contexts/DataContext.tsx`, add to the context interface and provider:

```typescript
reorderCategories: (categories: { categoryId: number; sortOrder: number }[]) => Promise<void>;
```

Implementation:

```typescript
const reorderCategories = useCallback(async (updates: { categoryId: number; sortOrder: number }[]) => {
  const result = await categoriesApi.reorder({ categories: updates });
  setCategories(result);
}, []);
```

- [ ] **Step 4: Run all frontend tests**

Run: `cd frontend && npm run test:run`
Expected: All tests pass (some may need type updates for missing `sortOrder` in mocks)

- [ ] **Step 5: Fix any test mocks that need sortOrder**

Add `sortOrder: 0` to any test mock Category objects that fail.

- [ ] **Step 6: Run all frontend tests again**

Run: `cd frontend && npm run test:run`
Expected: All 919+ tests pass

- [ ] **Step 7: Commit**

```bash
git add frontend/src/utils/types.ts frontend/src/api/categories.ts frontend/src/contexts/DataContext.tsx frontend/tests/
git commit -m "feat: add sortOrder to Category type and reorder API"
```

---

## Task 5: Frontend — SortConfirmModal Component

**Files:**
- Create: `frontend/src/components/category/SortConfirmModal.tsx`
- Create: `frontend/tests/SortConfirmModal.test.tsx`

- [ ] **Step 1: Write failing tests for SortConfirmModal**

Create `frontend/tests/SortConfirmModal.test.tsx`:

```typescript
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import SortConfirmModal from '../src/components/category/SortConfirmModal';

describe('SortConfirmModal', () => {
  it('renders both sort options', () => {
    render(<SortConfirmModal onConfirm={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByText(/this level only/i)).toBeInTheDocument();
    expect(screen.getByText(/all levels/i)).toBeInTheDocument();
  });

  it('calls onConfirm with "level" when This Level Only is clicked', () => {
    const onConfirm = vi.fn();
    render(<SortConfirmModal onConfirm={onConfirm} onCancel={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: /this level only/i }));
    expect(onConfirm).toHaveBeenCalledWith('level');
  });

  it('calls onConfirm with "all" when All Levels is clicked', () => {
    const onConfirm = vi.fn();
    render(<SortConfirmModal onConfirm={onConfirm} onCancel={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: /all levels/i }));
    expect(onConfirm).toHaveBeenCalledWith('all');
  });

  it('calls onCancel when Cancel is clicked', () => {
    const onCancel = vi.fn();
    render(<SortConfirmModal onConfirm={vi.fn()} onCancel={onCancel} />);
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalled();
  });

  it('displays warning about overwriting custom ordering', () => {
    render(<SortConfirmModal onConfirm={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByText(/overwrite/i)).toBeInTheDocument();
  });
});
```

Run: `cd frontend && npx vitest run tests/SortConfirmModal.test.tsx`
Expected: FAIL — component does not exist

- [ ] **Step 2: Implement SortConfirmModal**

Create `frontend/src/components/category/SortConfirmModal.tsx`:

```typescript
interface SortConfirmModalProps {
  onConfirm: (scope: 'level' | 'all') => void;
  onCancel: () => void;
}

function SortConfirmModal({ onConfirm, onCancel }: SortConfirmModalProps) {
  return (
    <div className="modal-overlay">
      <div className="modal" style={{ maxWidth: '420px' }}>
        <div className="modal__header">
          <h2 className="modal__title">Sort Categories Alphabetically</h2>
        </div>
        <div className="modal__body">
          <p className="modal__info">
            This will overwrite any custom ordering you have set.
          </p>
          <div className="modal__actions">
            <button
              type="button"
              className="modal__button modal__button--primary"
              onClick={() => onConfirm('level')}
              aria-label="This level only"
            >
              This Level Only
            </button>
            <button
              type="button"
              className="modal__button modal__button--primary"
              onClick={() => onConfirm('all')}
              aria-label="All levels"
            >
              All Levels
            </button>
          </div>
        </div>
        <div className="modal__footer">
          <button
            type="button"
            className="modal__button modal__button--secondary"
            onClick={onCancel}
            aria-label="Cancel"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

export default SortConfirmModal;
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cd frontend && npx vitest run tests/SortConfirmModal.test.tsx`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/category/SortConfirmModal.tsx frontend/tests/SortConfirmModal.test.tsx
git commit -m "feat: add SortConfirmModal component"
```

---

## Task 6: Frontend — CategoryManagerForm Component

**Files:**
- Create: `frontend/src/components/category/CategoryManagerForm.tsx`
- Create: `frontend/tests/CategoryManagerForm.test.tsx`

- [ ] **Step 1: Write failing tests for CategoryManagerForm**

Create `frontend/tests/CategoryManagerForm.test.tsx` with tests for:
- Renders empty state when no category is selected: "Select a category to edit, or click + to add a new one."
- Renders form fields (Name, Description, Parent Category, Templates, Visibility) when category selected
- Name field is required — Save button disabled when empty
- Validates reserved name "Unassigned Items"
- Calls `onSave` with updated fields when Save is clicked
- Calls `onDelete` when Delete is clicked
- Shows disabled fields with message for system categories
- Shows "Unpublish" button when category is public
- Shows "Publish" button when category is private
- Calls `onPublish` / `onUnpublish` for visibility actions
- Cancel button calls `onCancel`
- Shows create mode (empty fields, "Create" button text) when `isNew` prop is true

Mock `useData` for category templates. Mock `CategoryTemplateSelector` as a simple div.

Run: `cd frontend && npx vitest run tests/CategoryManagerForm.test.tsx`
Expected: FAIL — component does not exist

- [ ] **Step 2: Implement CategoryManagerForm**

Create `frontend/src/components/category/CategoryManagerForm.tsx`.

Props:
```typescript
interface CategoryManagerFormProps {
  category: Category | null;
  categories: Category[];
  collectionId: number;
  isNew: boolean;
  onSave: (updates: { name: string; description: string; parentCategoryId: number | null; itemTemplateIds: number[] }) => void;
  onDelete: (categoryId: number) => void;
  onPublish: (category: Category) => void;
  onUnpublish: (category: Category) => void;
  onCancel: () => void;
}
```

Port form logic from `CategoryEditorModal.tsx` (lines 65-96 for parent filtering, 87-96 for reserved name check, form fields from lines 216-277). Remove dialog/modal wrapping — this is a panel, not a modal.

Layout: header with category name + visibility badge, form fields, footer with Delete (left) and Cancel/Save (right).

- [ ] **Step 3: Run tests to verify they pass**

Run: `cd frontend && npx vitest run tests/CategoryManagerForm.test.tsx`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/category/CategoryManagerForm.tsx frontend/tests/CategoryManagerForm.test.tsx
git commit -m "feat: add CategoryManagerForm component"
```

---

## Task 7: Frontend — CategoryManagerTree Component

**Files:**
- Create: `frontend/src/components/category/CategoryManagerTree.tsx`
- Create: `frontend/tests/CategoryManagerTree.test.tsx`

- [ ] **Step 1: Write failing tests for CategoryManagerTree**

Create `frontend/tests/CategoryManagerTree.test.tsx` with tests for:
- Renders category hierarchy with correct indentation (root at 0, children indented)
- Shows accent color dots and chevrons for parent categories
- Highlights selected category with active styling
- Clicking a category calls `onSelect`
- Add button in toolbar calls `onAdd`
- Sort button in toolbar calls `onSortClick`
- Drag handle appears on each non-system category row
- Does not render drag handle for system categories
- Renders "root level" drop zone for reparenting to root

Mock `@dnd-kit` — don't test actual drag behavior in unit tests (that's integration testing territory). Test that the component renders the correct dnd-kit wrappers.

Run: `cd frontend && npx vitest run tests/CategoryManagerTree.test.tsx`
Expected: FAIL — component does not exist

- [ ] **Step 2: Implement CategoryManagerTree**

Create `frontend/src/components/category/CategoryManagerTree.tsx`.

Props:
```typescript
interface CategoryManagerTreeProps {
  categories: Category[];
  selectedCategoryId: number | null;
  onSelect: (categoryId: number) => void;
  onAdd: () => void;
  onSortClick: () => void;
  onReorder: (updates: { categoryId: number; sortOrder: number }[]) => void;
  onReparent: (categoryId: number, newParentId: number | null) => void;
}
```

Build tree structure using the same `buildCategoryTree` / `flattenWithIndent` pattern from `CategorySelector.tsx` (lines 12-46). Wrap in `DndContext` + `SortableContext` from `@dnd-kit`. Use `useSortable` per row. Include `DragOverlay` for visual feedback.

For reparenting: use `onDragOver` to detect when dragged item hovers over a different parent. Track `overParentId` state for visual highlight. On `onDragEnd`, if the item was dropped onto a different category (not just reordered), call `onReparent` instead of `onReorder`.

Circular reference prevention: compute descendants of the dragged category and disable those as drop targets.

- [ ] **Step 3: Run tests to verify they pass**

Run: `cd frontend && npx vitest run tests/CategoryManagerTree.test.tsx`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/category/CategoryManagerTree.tsx frontend/tests/CategoryManagerTree.test.tsx
git commit -m "feat: add CategoryManagerTree component with drag-and-drop"
```

---

## Task 8: Frontend — CategoryManagerModal Component

**Files:**
- Create: `frontend/src/components/category/CategoryManagerModal.tsx`
- Create: `frontend/src/components/category/CategoryManagerModal.css`
- Create: `frontend/tests/CategoryManagerModal.test.tsx`

- [ ] **Step 1: Write failing tests for CategoryManagerModal**

Create `frontend/tests/CategoryManagerModal.test.tsx` with tests for:
- Does not render when `isOpen` is false
- Renders modal with tree and empty form state when `isOpen` is true
- Loads categories on open via `loadCategoriesForCollection`
- Selecting a category in tree populates the form
- Saving a category calls `updateCategory` and refreshes tree
- Adding a new category switches form to create mode
- Deleting a category calls `deleteCategory`, clears selection
- Reordering calls `reorderCategories`
- Reparenting calls `updateCategory` with new parentCategoryId, then `reorderCategories`
- Publishing calls `publishCategory`
- Unpublishing calls `unpublishCategory` (with preview)
- Sort alphabetically opens SortConfirmModal
- Closing modal calls `onClose`

Mock `useData` to return categories and mock all category operations.

Run: `cd frontend && npx vitest run tests/CategoryManagerModal.test.tsx`
Expected: FAIL — component does not exist

- [ ] **Step 2: Create CategoryManagerModal.css**

Create `frontend/src/components/category/CategoryManagerModal.css` with styles for:
- `.categoryManager` — two-panel flex layout inside modal body
- `.categoryManager__tree` — left panel, 280px width, border-right, background matching CategoryNav
- `.categoryManager__form` — right panel, flex: 1
- `.categoryManager__toolbar` — header area in tree panel
- `.categoryManager__row` — tree row styles (reuse CategoryNav patterns)
- `.categoryManager__row--active` — selected row
- `.categoryManager__dragHandle` — grip dots, opacity 0, visible on hover
- `.categoryManager__rootDropZone` — drop zone indicator for reparenting to root

- [ ] **Step 3: Implement CategoryManagerModal**

Create `frontend/src/components/category/CategoryManagerModal.tsx`.

Props:
```typescript
interface CategoryManagerModalProps {
  collectionId: number;
  isOpen: boolean;
  onClose: () => void;
}
```

Uses native `<dialog>` element (matching existing modal pattern from `CategoryEditorModal.tsx`). State:
- `selectedCategoryId` — currently selected category
- `isNew` — whether form is in create mode
- `showSortConfirm` — whether SortConfirmModal is open

Orchestrates: CategoryManagerTree (left), CategoryManagerForm (right), SortConfirmModal (nested).

Handle sort alphabetically:
- `scope === 'level'`: Find siblings of selected category (same parentCategoryId), sort by name, assign sequential sortOrder, call `reorderCategories`.
- `scope === 'all'`: For each parent group in the tree, sort children by name, assign sequential sortOrder, collect all updates, call `reorderCategories`.

Handle reparent: call `updateCategory` with new `parentCategoryId`, then compute new sort orders for the target sibling group and call `reorderCategories`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npx vitest run tests/CategoryManagerModal.test.tsx`
Expected: PASS

- [ ] **Step 5: Run all frontend tests**

Run: `cd frontend && npm run test:run`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/category/CategoryManagerModal.tsx frontend/src/components/category/CategoryManagerModal.css frontend/tests/CategoryManagerModal.test.tsx
git commit -m "feat: add CategoryManagerModal with two-panel layout"
```

---

## Task 9: Frontend — Strip Inline Controls from CategoryNav

**Files:**
- Modify: `frontend/src/components/category/CategoryNav.tsx`
- Modify: `frontend/src/components/category/CategoryNav.css`
- Modify: `frontend/tests/CategoryNav.test.tsx`

- [ ] **Step 1: Update CategoryNav tests for read-only tree**

In `frontend/tests/CategoryNav.test.tsx`:
- Remove tests for: inline edit button (lines ~292-319), publish button (lines ~383-450), unpublish/public badge (lines ~452-565), add button behavior
- Remove snapshot tests that capture inline controls (lines ~567-581)
- Add new test: "renders Edit button in header that calls onEdit"
- Add new test: "does not render publish buttons on rows"
- Add new test: "does not render edit pencil buttons on rows"

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npx vitest run tests/CategoryNav.test.tsx`
Expected: FAIL — new tests fail (onEdit prop doesn't exist, old tests may also fail)

- [ ] **Step 3: Update CategoryNav component**

In `frontend/src/components/category/CategoryNav.tsx`:

Update props interface — add `onEdit` callback, remove `onCollapse` if it's only used for collapse (keep if still needed):
```typescript
interface CategoryNavProps {
  categories: Category[];
  selectedCategoryId: number | null;
  onSelect: (categoryId: number | null) => void;
  onCollapse?: () => void;
  onEdit?: () => void;
}
```

Remove from component:
- All publish/unpublish state and handlers (lines 36-39, 144-186)
- `PublishButton`, `PublicBadge`, `PublishConfirmModal`, `UnpublishConfirmModal`, `SlugSetupModal` imports (line 10)
- `CategoryEditorModal` import and state (lines 9, 34-35, 120-142)
- Inline publish/badge elements from row rendering (lines 335-346)
- Inline edit button from row rendering (lines 348-360)
- All modal rendering at bottom (lines 374-406)
- `useData` calls for publish/unpublish/loadCategories (lines 28-31)

Replace header `+` button with Edit button:
```tsx
<button
  type="button"
  className="categoryNav__editBtn"
  onClick={onEdit}
  aria-label="Edit categories"
>
  &#9998;
</button>
```

Keep: collapse button, category rows (name, dot, chevron, click to select), breadcrumbs, back button, drill-down navigation, loading/error states.

- [ ] **Step 4: Update CategoryNav.css**

Remove styles for: `.categoryNav__publish-btn`, `.categoryNav__badge`, `.categoryNav__edit`, and their hover/focus-within rules (lines 186-226).

Add style for `.categoryNav__editBtn` (reuse the same 28x28 button style as `.categoryNav__addBtn`).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd frontend && npx vitest run tests/CategoryNav.test.tsx`
Expected: PASS

- [ ] **Step 6: Run all frontend tests**

Run: `cd frontend && npm run test:run`
Expected: Some tests in CategoryView.test.tsx may fail — that's expected, we'll fix in the next task

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/category/CategoryNav.tsx frontend/src/components/category/CategoryNav.css frontend/tests/CategoryNav.test.tsx
git commit -m "refactor: make CategoryNav read-only, add Edit button"
```

---

## Task 10: Frontend — Wire Up Entry Points

**Files:**
- Modify: `frontend/src/views/CategoryView.tsx`
- Modify: `frontend/src/views/SettingsView.tsx`
- Modify: `frontend/src/components/category/index.ts`
- Modify: `frontend/tests/views/CategoryView.test.tsx`

- [ ] **Step 1: Update barrel exports**

In `frontend/src/components/category/index.ts`, add:

```typescript
export { default as CategoryManagerModal } from './CategoryManagerModal';
export { default as SortConfirmModal } from './SortConfirmModal';
```

Remove (if no longer imported elsewhere):
```typescript
export { default as CategoryEditorModal } from './CategoryEditorModal';
```

- [ ] **Step 2: Update CategoryView to wire up CategoryManagerModal**

In `frontend/src/views/CategoryView.tsx`:

Add state:
```typescript
const [categoryManagerOpen, setCategoryManagerOpen] = useState(false);
```

Pass `onEdit` to CategoryNav:
```tsx
<CategoryNav
  categories={categories}
  selectedCategoryId={categoryIdNum}
  onSelect={handleSelectCategory}
  onCollapse={() => setSidebarCollapsed(true)}
  onEdit={() => setCategoryManagerOpen(true)}
/>
```

Render CategoryManagerModal (before closing `</div>`):
```tsx
{categoryManagerOpen && currentCollection && (
  <CategoryManagerModal
    collectionId={currentCollection.collectionId}
    isOpen={categoryManagerOpen}
    onClose={() => setCategoryManagerOpen(false)}
  />
)}
```

Do this for both render branches (no category selected at line ~275 and category selected at line ~356).

- [ ] **Step 3: Update SettingsView to add Categories button**

In `frontend/src/views/SettingsView.tsx`, in the collection card actions area (around line 454), add a "Categories" button:

```tsx
<button onClick={() => setEditingCollectionCategories(collection)}>
  Categories
</button>
```

Add state for `editingCollectionCategories` and render `CategoryManagerModal` when set.

- [ ] **Step 4: Update CategoryView tests**

In `frontend/tests/views/CategoryView.test.tsx`:
- Remove tests that expect inline publish/edit controls on CategoryNav rows
- Add test: "clicking Edit button in CategoryNav opens CategoryManagerModal"
- Add test: "CategoryManagerModal receives correct collectionId"

- [ ] **Step 5: Run all frontend tests**

Run: `cd frontend && npm run test:run`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/category/index.ts frontend/src/views/CategoryView.tsx frontend/src/views/SettingsView.tsx frontend/tests/
git commit -m "feat: wire CategoryManagerModal to CategoryNav and SettingsView"
```

---

## Task 11: Cleanup and Final Verification

**Files:**
- Possibly remove: `frontend/src/components/category/CategoryEditorModal.tsx` (if no longer used)
- Modify: Any remaining test files with stale references

- [ ] **Step 1: Check if CategoryEditorModal is still imported anywhere**

Search for imports of `CategoryEditorModal` across the codebase. If no other component uses it, delete the file and its test.

- [ ] **Step 2: Remove CategoryEditorModal if unused**

Delete `frontend/src/components/category/CategoryEditorModal.tsx` and update `index.ts` if the export was kept.

- [ ] **Step 3: Run all backend tests**

Run: `dotnet test backend/tests/backend.tests`
Expected: All tests pass

- [ ] **Step 4: Run all frontend tests**

Run: `cd frontend && npm run test:run`
Expected: All tests pass

- [ ] **Step 5: Run frontend lint**

Run: `cd frontend && npm run lint`
Expected: No errors

- [ ] **Step 6: Run frontend build**

Run: `cd frontend && npm run build`
Expected: Build succeeds

- [ ] **Step 7: Commit any remaining cleanup**

```bash
git add -A
git commit -m "chore: remove unused CategoryEditorModal, final cleanup"
```
