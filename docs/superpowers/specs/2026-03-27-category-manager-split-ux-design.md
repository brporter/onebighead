# Category Manager Split UX Design

## Overview

Redesign the CategoryManager modal from a side-by-side layout (tree + form always visible) to a single-panel experience with animated transitions between a tree view and an edit/create form. Adds a quick-create popover for rapid category creation with just a name.

## Motivation

The current side-by-side layout is space-constrained and difficult to use. The tree panel is fixed at 280px, leaving limited room for the form. By giving each view the full modal width, both the tree and the form get more room to breathe.

## Approach

**Approach A: Single Component with View State** — Keep `CategoryManagerModal` as the orchestrator with a `view` state. Both tree and form render inside a sliding track container controlled by CSS `transform: translateX()` with transitions. No new dependencies.

## Layout & Slide Mechanism

### Container Architecture

The modal body becomes a viewport with `overflow: hidden`. Inside it, a track div holds both panels side by side, each taking 50% of the track width (which is 200% of the viewport).

- **Tree view**: `transform: translateX(0)` — tree visible, form off-screen right
- **Form view**: `transform: translateX(-50%)` — tree off-screen left, form visible
- **Transition**: `transition: transform 300ms ease-in-out` on the track

### Footer Behavior

The footer (Delete / Cancel / Save buttons) only renders when `view === 'form'`. The tree view has no footer action buttons.

### Modal Close (×)

- **Tree view**: Closes modal immediately
- **Form view, no changes**: Slides back to tree (does not close modal)
- **Form view, has changes**: Shows discard confirmation, then slides back to tree

## Interaction Flows

### Flow 1: Click Category Row → Edit

User clicks a category row in the tree. Sets `selectedCategoryId` and `view = 'form'`. Tree slides left, form slides in populated with the selected category's data. Footer appears with Delete / Cancel / Save.

### Flow 2: Quick Create (+ Button)

User clicks the + button. A popover drops down from the button with a single name input field and three buttons:

- **Save**: Creates the category via API with name only. Category is added to the top of the root-level sort order. Popover closes. Stays on tree view.
- **More Details**: Closes popover. Sets `isNew = true`, `selectedCategoryId = null`. Slides to form view with the typed name pre-filled via `initialName` prop.
- **Cancel**: Closes popover. No changes.

Click-outside and Escape key also dismiss the popover (same as Cancel). Enter key triggers Save.

### Flow 3: Navigation Away from Form

Three ways to leave the form view — all follow the same pattern:

- **← Back to Categories link**: If no changes, slides to tree. If changes, shows discard confirmation first.
- **Cancel button**: Disabled when no changes. If changes, shows discard confirmation, then slides to tree.
- **× Close modal button**: If no changes, slides to tree. If changes, shows discard confirmation, then slides to tree.

### Flow 4: Save & Delete

- **Save/Create**: Validates form, calls API, reloads categories, slides back to tree.
- **Delete**: Shows delete confirmation modal. On confirm, calls API, reloads categories, slides back to tree.

## Component Structure

### New: QuickCreatePopover

Small, focused component anchored to the + button via absolute positioning.

**Props:**
- `isVisible: boolean`
- `anchorRef: RefObject<HTMLButtonElement>` — positions relative to the + button
- `onSave: (name: string) => void`
- `onMoreDetails: (name: string) => void`
- `onCancel: () => void`

**Behavior:**
- Auto-focuses name input on open
- Validates name (not empty, not reserved) before Save
- Click-outside dismisses (same as Cancel)
- Enter key triggers Save, Escape triggers Cancel

### Modified: CategoryManagerModal

- Adds `view: 'tree' | 'form'` state
- Adds `showQuickCreate: boolean` and `initialName: string` state
- Removes auto-select first category on open — always opens to tree view
- Replaces side-by-side flex layout with overflow-hidden viewport + sliding track
- Updates close (×) behavior: tree view closes modal; form view returns to tree (with discard confirm if changes)
- Handles quick-create Save (API call, reload, add to top of sort order)
- Handles quick-create More Details (close popover, slide to form with name)

### Modified: CategoryManagerTree

- Row click now calls `onEditCategory(categoryId)` instead of selection
- Removes active row highlighting (`.catTree__row--active`)
- Removes `selectedCategoryId` prop
- Adds `onEditCategory: (id: number) => void` prop
- Adds `onQuickCreate: () => void` prop (+ button handler)
- Keeps all drag-and-drop functionality unchanged

### Modified: CategoryManagerForm

- Adds "← Back to Categories" link at the top
- Adds `onBack: () => void` prop
- Adds `initialName?: string` prop for quick-create handoff
- Footer (Delete / Cancel / Save) moves from modal level into the form panel
- All form fields, validation, and submission logic unchanged

### Unchanged

- `categoryManagerTreeUtils.ts` — tree building, flattening, reorder computation
- `CategoryTemplateSelector` — template checkbox UI used inside form
- All confirmation modals — delete, discard, publish, unpublish, slug setup

## State Management

### State Variables (CategoryManagerModal)

| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `view` | `'tree' \| 'form'` | `'tree'` | Controls slide track position |
| `showQuickCreate` | `boolean` | `false` | Controls popover visibility |
| `initialName` | `string` | `''` | Name passed from popover to form via "More Details" |
| `selectedCategoryId` | `number \| null` | `null` | Category being edited (kept) |
| `isNew` | `boolean` | `false` | Create vs edit mode (kept) |
| `formHasChanges` | `boolean` | `false` | Drives discard confirmation (kept) |

Confirmation modal states (`showDeleteConfirm`, `showCancelConfirm`, `publishTarget`, `unpublishTarget`, `unpublishPreview`, `showSlugSetup`) are all kept unchanged.

### State Transitions

**Tree view (`view = 'tree'`):**
- Click category row → `selectedCategoryId = id, isNew = false, view = 'form'`
- Click + button → `showQuickCreate = true`
- Drag & drop → reorder/reparent API call, reload (stays on tree)
- Click × → close modal

**Quick create popover (`showQuickCreate = true`):**
- Save → API create, reload, `showQuickCreate = false` (stay on tree)
- More Details → `showQuickCreate = false, isNew = true, selectedCategoryId = null, view = 'form'`
- Cancel / click outside → `showQuickCreate = false, initialName = ''`

**Form view (`view = 'form'`):**
- ← Back (no changes) → `view = 'tree', selectedCategoryId = null`
- ← Back (has changes) → show discard confirm → `view = 'tree', selectedCategoryId = null`
- Save / Create → API call, reload, `view = 'tree', selectedCategoryId = null`
- Delete (confirmed) → API delete, reload, `view = 'tree', selectedCategoryId = null`
- × close (has changes) → show discard confirm → `view = 'tree'`

### Modal Open Reset

When the modal opens, all state resets: `view = 'tree'`, `selectedCategoryId = null`, `isNew = false`, `formHasChanges = false`, `showQuickCreate = false`, `initialName = ''`. Categories load fresh from API.

## CSS Changes

### CategoryManagerModal.css

- `.categoryManager` — changes from `display: flex` (row) to `overflow: hidden` viewport
- `.categoryManager__track` — new class: `display: flex; width: 200%; transition: transform 300ms ease-in-out`
- `.categoryManager__track--form` — `transform: translateX(-50%)`
- `.categoryManager__tree` — changes from `width: 280px` to `width: 50%`
- `.categoryManager__form` — changes from `flex: 1` to `width: 50%`
- `.categoryManager__footer` — moves inside form panel (no longer at modal level)
- `.catTree__row--active` — removed (no selection state)
- `.quickCreatePopover` — new: absolute positioning, shadow, border radius
- `.quickCreatePopover__input` — name input styling
- `.quickCreatePopover__actions` — button row styling

## Testing Strategy

### CategoryManagerModal.test.tsx (update + new)

**Update existing:**
- Remove auto-select first category tests
- Replace "select category in tree" with "click row slides to form"
- Update close behavior tests for tree vs form view
- Update save/delete to verify slide back to tree

**New tests:**
- Opens to tree view by default
- View state toggles slide track class
- Click row → sets selectedId + view='form'
- Quick create Save → API call + stays on tree
- Quick create More Details → popover closes + slides to form with name
- Quick create Cancel → popover closes
- × close from form with changes → discard → back to tree (not close)
- × close from form without changes → back to tree
- × close from tree → closes modal
- State resets on modal open

### CategoryManagerForm.test.tsx (update + new)

**Update existing:**
- Add back link rendering assertions
- Add footer rendering within form panel

**New tests:**
- Back link click calls onBack
- initialName prop pre-fills name field
- Footer renders inside form (not modal level)

### CategoryManagerTree.test.tsx (update + new)

**Update existing:**
- Remove active row highlight tests
- Row click now calls onEditCategory

**New tests:**
- Click row fires onEditCategory(id)
- No active/selected styling on rows

### QuickCreatePopover.test.tsx (new)

- Renders when visible
- Does not render when hidden
- Name input focuses on open
- Save calls onSave with name
- Save with empty name shows validation error
- Save with reserved name shows validation error
- More Details calls onMoreDetails with name
- Cancel calls onCancel
- Click outside calls onCancel
- Enter key in input triggers Save
- Escape key triggers Cancel

### categoryManagerTreeUtils.test.ts (unchanged)

No changes needed — tree building, flattening, and reorder logic are unaffected.
