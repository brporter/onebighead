# Category Manager Split UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the CategoryManager modal from a side-by-side layout to a single-panel experience with animated slide transitions between tree view and edit form, plus a quick-create popover for rapid category creation.

**Architecture:** The modal body becomes an overflow-hidden viewport containing a sliding track div (200% width) with tree and form panels at 50% each. A single `view` state (`'tree' | 'form'`) drives `transform: translateX()` with CSS transitions. A new `QuickCreatePopover` component drops from the + button for name-only creation.

**Tech Stack:** React 19, CSS transitions (transform + transition), @dnd-kit (existing), Vitest + React Testing Library

**Spec:** `docs/superpowers/specs/2026-03-27-category-manager-split-ux-design.md`

---

## File Map

| Action | File | Responsibility |
|--------|------|---------------|
| Modify | `frontend/src/components/category/CategoryManagerModal.tsx` | Add view state, slide track, quick-create handling, updated close behavior |
| Modify | `frontend/src/components/category/CategoryManagerModal.css` | Slide track styles, remove side-by-side layout, add popover styles |
| Modify | `frontend/src/components/category/CategoryManagerTree.tsx` | Row click → onEditCategory, remove selection props/styling |
| Modify | `frontend/src/components/category/CategoryManagerForm.tsx` | Add back link, initialName prop, integrate footer |
| Create | `frontend/src/components/category/QuickCreatePopover.tsx` | Name-only popover anchored to + button |
| Modify | `frontend/src/components/category/index.ts` | Export QuickCreatePopover |
| Create | `frontend/tests/QuickCreatePopover.test.tsx` | Full test suite for new component |
| Modify | `frontend/tests/CategoryManagerModal.test.tsx` | Update for new view state, quick-create, close behavior |
| Modify | `frontend/tests/CategoryManagerTree.test.tsx` | Update for onEditCategory, remove selection tests |
| Modify | `frontend/tests/CategoryManagerForm.test.tsx` | Add back link, initialName, footer tests |

---

### Task 1: Create QuickCreatePopover Component + Tests

**Files:**
- Create: `frontend/src/components/category/QuickCreatePopover.tsx`
- Create: `frontend/tests/QuickCreatePopover.test.tsx`
- Modify: `frontend/src/components/category/index.ts`

- [ ] **Step 1: Write the QuickCreatePopover test file**

```tsx
// frontend/tests/QuickCreatePopover.test.tsx
import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import QuickCreatePopover from '../src/components/category/QuickCreatePopover';

describe('QuickCreatePopover', () => {
  const defaultProps = {
    isVisible: true,
    onSave: vi.fn(),
    onMoreDetails: vi.fn(),
    onCancel: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render when visible', () => {
    render(<QuickCreatePopover {...defaultProps} />);
    expect(screen.getByPlaceholderText('Category name')).toBeInTheDocument();
  });

  it('should not render when not visible', () => {
    render(<QuickCreatePopover {...defaultProps} isVisible={false} />);
    expect(screen.queryByPlaceholderText('Category name')).not.toBeInTheDocument();
  });

  it('should focus name input on open', async () => {
    render(<QuickCreatePopover {...defaultProps} />);
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Category name')).toHaveFocus();
    });
  });

  it('should call onSave with trimmed name when Save clicked', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.type(screen.getByPlaceholderText('Category name'), '  New Category  ');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    expect(defaultProps.onSave).toHaveBeenCalledWith('New Category');
  });

  it('should show validation error when Save clicked with empty name', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.click(screen.getByRole('button', { name: 'Save' }));

    expect(screen.getByRole('alert')).toHaveTextContent('Name is required');
    expect(defaultProps.onSave).not.toHaveBeenCalled();
  });

  it('should show validation error for reserved name', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.type(screen.getByPlaceholderText('Category name'), 'Unassigned Items');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    expect(screen.getByRole('alert')).toHaveTextContent('reserved name');
    expect(defaultProps.onSave).not.toHaveBeenCalled();
  });

  it('should call onMoreDetails with current name when More Details clicked', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.type(screen.getByPlaceholderText('Category name'), 'My Category');
    await user.click(screen.getByRole('button', { name: 'More Details...' }));

    expect(defaultProps.onMoreDetails).toHaveBeenCalledWith('My Category');
  });

  it('should call onMoreDetails with empty string when name is empty', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.click(screen.getByRole('button', { name: 'More Details...' }));

    expect(defaultProps.onMoreDetails).toHaveBeenCalledWith('');
  });

  it('should call onCancel when Cancel clicked', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(defaultProps.onCancel).toHaveBeenCalled();
  });

  it('should call onSave when Enter pressed in input', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.type(screen.getByPlaceholderText('Category name'), 'Quick Cat{Enter}');

    expect(defaultProps.onSave).toHaveBeenCalledWith('Quick Cat');
  });

  it('should call onCancel when Escape pressed in input', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.type(screen.getByPlaceholderText('Category name'), 'Something');
    await user.keyboard('{Escape}');

    expect(defaultProps.onCancel).toHaveBeenCalled();
  });

  it('should reset name when becoming visible again', async () => {
    const { rerender } = render(<QuickCreatePopover {...defaultProps} isVisible={false} />);

    rerender(<QuickCreatePopover {...defaultProps} isVisible={true} />);

    expect(screen.getByPlaceholderText('Category name')).toHaveValue('');
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npx vitest run tests/QuickCreatePopover.test.tsx`
Expected: FAIL — QuickCreatePopover module not found

- [ ] **Step 3: Write the QuickCreatePopover component**

```tsx
// frontend/src/components/category/QuickCreatePopover.tsx
import React, { useState, useEffect, useRef } from 'react';

const RESERVED_NAMES = ['unassigned items'];

interface QuickCreatePopoverProps {
  isVisible: boolean;
  onSave: (name: string) => void;
  onMoreDetails: (name: string) => void;
  onCancel: () => void;
}

function QuickCreatePopover({ isVisible, onSave, onMoreDetails, onCancel }: QuickCreatePopoverProps) {
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Reset and focus when popover opens
  useEffect(() => {
    if (isVisible) {
      setName('');
      setError(null);
      // Focus after render
      requestAnimationFrame(() => {
        inputRef.current?.focus();
      });
    }
  }, [isVisible]);

  if (!isVisible) return null;

  const validateAndSave = () => {
    const trimmed = name.trim();
    if (!trimmed) {
      setError('Name is required');
      return;
    }
    if (RESERVED_NAMES.includes(trimmed.toLowerCase())) {
      setError(`"${trimmed}" is a reserved name and cannot be used`);
      return;
    }
    onSave(trimmed);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      validateAndSave();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      onCancel();
    }
  };

  return (
    <div className="quickCreatePopover">
      <input
        ref={inputRef}
        type="text"
        className="quickCreatePopover__input modal__input"
        placeholder="Category name"
        value={name}
        onChange={(e) => {
          setName(e.target.value);
          setError(null);
        }}
        onKeyDown={handleKeyDown}
      />
      {error && (
        <div className="quickCreatePopover__error modal__error" role="alert">
          {error}
        </div>
      )}
      <div className="quickCreatePopover__actions">
        <button
          type="button"
          className="modal__button modal__button--secondary"
          onClick={() => onMoreDetails(name)}
        >
          More Details...
        </button>
        <button
          type="button"
          className="modal__button modal__button--secondary"
          onClick={onCancel}
        >
          Cancel
        </button>
        <button
          type="button"
          className="modal__button modal__button--primary"
          onClick={validateAndSave}
        >
          Save
        </button>
      </div>
    </div>
  );
}

export default QuickCreatePopover;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npx vitest run tests/QuickCreatePopover.test.tsx`
Expected: All 10 tests PASS

- [ ] **Step 5: Add QuickCreatePopover to barrel export**

In `frontend/src/components/category/index.ts`, add this line with the other exports:

```ts
export { default as QuickCreatePopover } from './QuickCreatePopover';
```

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/category/QuickCreatePopover.tsx frontend/tests/QuickCreatePopover.test.tsx frontend/src/components/category/index.ts
git commit -m "feat: add QuickCreatePopover component for rapid category creation"
```

---

### Task 2: Update CategoryManagerTree — Remove Selection, Add onEditCategory

**Files:**
- Modify: `frontend/src/components/category/CategoryManagerTree.tsx`
- Modify: `frontend/tests/CategoryManagerTree.test.tsx`

- [ ] **Step 1: Update CategoryManagerTree tests for new behavior**

In `frontend/tests/CategoryManagerTree.test.tsx`, make these changes:

1. Update the props interface reference — replace `onSelect` with `onEditCategory` and remove `selectedCategoryId`:

Find the section where `defaultProps` is defined (around the `describe` block) and update. Replace the `defaultProps` object to use:
```ts
const defaultProps = {
  categories: mockCategories,
  onEditCategory: vi.fn(),
  onAdd: vi.fn(),
  onReorder: vi.fn(),
  onReparent: vi.fn(),
};
```

2. Replace all occurrences of `onSelect` with `onEditCategory` in tests.

3. Remove any `selectedCategoryId` prop from defaultProps.

4. Remove the test that checks for `catTree__row--active` styling. Add this test instead:

```ts
it('should not apply active styling to any row', () => {
  render(<CategoryManagerTree {...defaultProps} />);
  const rows = document.querySelectorAll('.catTree__row');
  rows.forEach(row => {
    expect(row.classList.contains('catTree__row--active')).toBe(false);
  });
});
```

5. Update existing "click fires callback" test to use `onEditCategory`:

```ts
it('should call onEditCategory when row is clicked', async () => {
  const user = userEvent.setup();
  render(<CategoryManagerTree {...defaultProps} />);
  const rows = screen.getAllByRole('button');
  // Click first non-system row
  await user.click(rows[0]);
  expect(defaultProps.onEditCategory).toHaveBeenCalledWith(expect.any(Number));
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npx vitest run tests/CategoryManagerTree.test.tsx`
Expected: FAIL — `onEditCategory` not in props, `selectedCategoryId` still expected

- [ ] **Step 3: Update CategoryManagerTree component**

In `frontend/src/components/category/CategoryManagerTree.tsx`:

1. **Update the interface** (lines 36-43). Replace:
```ts
export interface CategoryManagerTreeProps {
  categories: Category[];
  selectedCategoryId: number | null;
  onSelect: (categoryId: number) => void;
  onAdd: () => void;
  onReorder: (updates: { categoryId: number; sortOrder: number }[]) => void;
  onReparent: (categoryId: number, newParentId: number | null) => void;
}
```
With:
```ts
export interface CategoryManagerTreeProps {
  categories: Category[];
  onEditCategory: (categoryId: number) => void;
  onAdd: () => void;
  onReorder: (updates: { categoryId: number; sortOrder: number }[]) => void;
  onReparent: (categoryId: number, newParentId: number | null) => void;
}
```

2. **Update SortableRowProps** (lines 57-63). Remove `isSelected` prop:
```ts
interface SortableRowProps {
  row: FlatRow;
  onEditCategory: (categoryId: number) => void;
  dropIntent: DropIntent;
  isDisabledTarget: boolean;
}
```

3. **Update SortableRow** (line 65). Remove `isSelected` from destructuring, replace `onSelect` with `onEditCategory`:
```ts
function SortableRow({ row, onEditCategory, dropIntent, isDisabledTarget }: SortableRowProps) {
```

4. **Remove active class logic** (line 87). Remove the line:
```ts
  if (isSelected) className += ' catTree__row--active';
```

5. **Update onClick and onKeyDown** (lines 99, 105). Change `onSelect` to `onEditCategory`:
```ts
      onClick={() => onEditCategory(row.category.categoryId)}
      ...
          onEditCategory(row.category.categoryId);
```

6. **Update function signature** (line 137-144). Destructure `onEditCategory` instead of `onSelect` and remove `selectedCategoryId`:
```ts
function CategoryManagerTree({
  categories,
  onEditCategory,
  onAdd,
  onReorder,
  onReparent,
}: CategoryManagerTreeProps) {
```

7. **Update SortableRow usage** (lines 315-323). Remove `isSelected` prop, change `onSelect` to `onEditCategory`:
```tsx
                <SortableRow
                  key={rowId}
                  row={row}
                  onEditCategory={onEditCategory}
                  dropIntent={rowDropIntent}
                  isDisabledTarget={disabledTargetIds.has(rowId)}
                />
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npx vitest run tests/CategoryManagerTree.test.tsx`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/category/CategoryManagerTree.tsx frontend/tests/CategoryManagerTree.test.tsx
git commit -m "refactor: replace onSelect with onEditCategory in CategoryManagerTree, remove selection state"
```

---

### Task 3: Update CategoryManagerForm — Add Back Link, initialName, Footer

**Files:**
- Modify: `frontend/src/components/category/CategoryManagerForm.tsx`
- Modify: `frontend/tests/CategoryManagerForm.test.tsx`

- [ ] **Step 1: Update CategoryManagerForm tests**

In `frontend/tests/CategoryManagerForm.test.tsx`, add new tests and update existing ones. Add these props to `defaultProps`:

```ts
const defaultProps = {
  category: null as Category | null,
  categories: mockCategories,
  collectionId: 1,
  isNew: false,
  onSave: vi.fn(),
  onPublish: vi.fn(),
  onUnpublish: vi.fn(),
  onHasChanges: vi.fn(),
  onBack: vi.fn(),
  onDelete: vi.fn(),
  onCancel: vi.fn(),
  formRef: { current: null },
  initialName: '',
};
```

Add these new test cases inside the `describe('CategoryManagerForm', ...)` block:

```ts
describe('back link', () => {
  it('should render back link', () => {
    render(<CategoryManagerForm {...defaultProps} isNew={true} />);
    expect(screen.getByText('← Back to Categories')).toBeInTheDocument();
  });

  it('should call onBack when back link is clicked', async () => {
    const user = userEvent.setup();
    render(<CategoryManagerForm {...defaultProps} isNew={true} />);
    await user.click(screen.getByText('← Back to Categories'));
    expect(defaultProps.onBack).toHaveBeenCalled();
  });
});

describe('initialName', () => {
  it('should pre-fill name field with initialName when in create mode', () => {
    render(<CategoryManagerForm {...defaultProps} isNew={true} initialName="Pre-filled" />);
    expect(screen.getByDisplayValue('Pre-filled')).toBeInTheDocument();
  });

  it('should not use initialName in edit mode', () => {
    const cat = makeCategory({ name: 'Existing' });
    render(<CategoryManagerForm {...defaultProps} category={cat} isNew={false} initialName="Pre-filled" />);
    expect(screen.getByDisplayValue('Existing')).toBeInTheDocument();
    expect(screen.queryByDisplayValue('Pre-filled')).not.toBeInTheDocument();
  });
});

describe('footer', () => {
  it('should render footer with Cancel and Save/Create buttons in create mode', () => {
    render(<CategoryManagerForm {...defaultProps} isNew={true} />);
    expect(screen.getByRole('button', { name: 'Create' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
  });

  it('should render footer with Delete, Cancel and Save Changes in edit mode', () => {
    const cat = makeCategory();
    render(<CategoryManagerForm {...defaultProps} category={cat} />);
    expect(screen.getByRole('button', { name: 'Save Changes' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
  });

  it('should not render Delete button for system categories', () => {
    const cat = makeCategory({ isSystem: true });
    render(<CategoryManagerForm {...defaultProps} category={cat} />);
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  });

  it('should call onCancel when Cancel clicked', async () => {
    const user = userEvent.setup();
    render(<CategoryManagerForm {...defaultProps} isNew={true} />);
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(defaultProps.onCancel).toHaveBeenCalled();
  });

  it('should call onDelete when Delete clicked', async () => {
    const user = userEvent.setup();
    const cat = makeCategory();
    render(<CategoryManagerForm {...defaultProps} category={cat} />);
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    expect(defaultProps.onDelete).toHaveBeenCalled();
  });

  it('should have Cancel disabled when no changes', () => {
    const cat = makeCategory();
    render(<CategoryManagerForm {...defaultProps} category={cat} />);
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npx vitest run tests/CategoryManagerForm.test.tsx`
Expected: FAIL — missing onBack, onDelete, onCancel props; no back link or footer rendered

- [ ] **Step 3: Update CategoryManagerForm component**

In `frontend/src/components/category/CategoryManagerForm.tsx`:

1. **Update the interface** (lines 5-15). Add new props:
```ts
interface CategoryManagerFormProps {
  category: Category | null;
  categories: Category[];
  collectionId: number;
  isNew: boolean;
  initialName?: string;
  onSave: (updates: { name: string; description: string; parentCategoryId: number | null; itemTemplateIds: number[] }) => void;
  onBack: () => void;
  onDelete: () => void;
  onCancel: () => void;
  onPublish: (category: Category) => void;
  onUnpublish: (category: Category) => void;
  onHasChanges?: (hasChanges: boolean) => void;
  formRef?: React.RefObject<{ submit: () => void } | null>;
}
```

2. **Update destructuring** (lines 19-29). Add `initialName`, `onBack`, `onDelete`, `onCancel`:
```ts
function CategoryManagerForm({
  category,
  categories,
  collectionId,
  isNew,
  initialName = '',
  onSave,
  onBack,
  onDelete,
  onCancel,
  onPublish,
  onUnpublish,
  onHasChanges,
  formRef,
}: CategoryManagerFormProps) {
```

3. **Update the reset effect** (lines 79-95). Use `initialName` when in create mode:
```ts
  useEffect(() => {
    /* eslint-disable react-hooks/set-state-in-effect -- Synchronizing form state with selected category prop */
    if (isNew) {
      setName(initialName);
      setDescription('');
      setParentCategoryId(null);
      setItemTemplateIds([]);
      setError(null);
    } else if (category) {
      setName(category.name);
      setDescription(category.description);
      setParentCategoryId(category.parentCategoryId);
      setItemTemplateIds(category.itemTemplateIds);
      setError(null);
    }
    /* eslint-enable react-hooks/set-state-in-effect */
  }, [category, isNew, initialName]);
```

4. **Update the transient state render** (lines 137-140). Show back link even in transient state:
```ts
  if (!category && !isNew) {
    return <div className="category-manager-form" />;
  }
```

5. **Add back link at the top of the main return** (inside the `.category-manager-form` div, before the existing header). Insert this above the `{category && (` header block at line 176:
```tsx
      <button
        type="button"
        className="category-manager-form__back"
        onClick={onBack}
      >
        ← Back to Categories
      </button>
```

6. **Add footer at the bottom of the form** (before the closing `</div>` of `.category-manager-form`, after the `</form>` tag). Insert after line 279:
```tsx
      <div className="categoryManager__footer">
        {category && !isNew && !category.isSystem ? (
          <button
            type="button"
            className="modal__button modal__button--danger"
            onClick={onDelete}
          >
            Delete
          </button>
        ) : (
          <div />
        )}
        <div className="categoryManager__footer-right">
          <button
            type="button"
            className="modal__button modal__button--secondary"
            onClick={onCancel}
            disabled={!hasChanges}
          >
            Cancel
          </button>
          <button
            type="button"
            className="modal__button modal__button--primary"
            onClick={() => formRef?.current?.submit()}
          >
            {isNew ? 'Create' : 'Save Changes'}
          </button>
        </div>
      </div>
```

7. **Also add the back link and footer to the system category view** (lines 142-169). Add the back link before the header, and do NOT add footer for system categories (they're read-only).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npx vitest run tests/CategoryManagerForm.test.tsx`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/category/CategoryManagerForm.tsx frontend/tests/CategoryManagerForm.test.tsx
git commit -m "feat: add back link, initialName prop, and footer to CategoryManagerForm"
```

---

### Task 4: Update CSS — Slide Track Layout + Popover Styles

**Files:**
- Modify: `frontend/src/components/category/CategoryManagerModal.css`

- [ ] **Step 1: Update the CSS file**

Replace the layout section of `frontend/src/components/category/CategoryManagerModal.css`. The changes:

1. **Replace `.categoryManager` rule** (lines 11-16):
```css
.categoryManager {
  position: relative;
  min-height: 500px;
  max-height: 70vh;
  overflow: hidden;
}
```

2. **Add slide track rules** (after `.categoryManager`):
```css
.categoryManager__track {
  display: flex;
  width: 200%;
  height: 100%;
  transition: transform 300ms ease-in-out;
}

.categoryManager__track--form {
  transform: translateX(-50%);
}
```

3. **Replace `.categoryManager__tree` rule** (lines 18-25):
```css
.categoryManager__tree {
  width: 50%;
  background: var(--color-surface-alt);
  overflow-y: auto;
  padding: var(--space-lg);
}
```

4. **Replace `.categoryManager__form` rule** (lines 27-31):
```css
.categoryManager__form {
  width: 50%;
  overflow-y: auto;
  padding: var(--space-md);
  display: flex;
  flex-direction: column;
}
```

5. **Remove `.catTree__row--active` rule** (lines 121-124). Delete this entire block:
```css
.catTree__row--active {
  background: var(--color-accent-subtle);
  border-left: 3px solid var(--color-accent);
}
```

6. **Add popover styles** (at the end of the file):
```css
/* ==========================================================================
   QuickCreatePopover — dropdown from + button
   ========================================================================== */

.quickCreatePopover {
  position: absolute;
  top: 100%;
  right: 0;
  z-index: 10;
  min-width: 300px;
  margin-top: var(--space-xs);
  padding: var(--space-md);
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
}

.quickCreatePopover__input {
  margin-bottom: var(--space-sm);
}

.quickCreatePopover__error {
  margin-bottom: var(--space-sm);
  font-size: 0.85rem;
}

.quickCreatePopover__actions {
  display: flex;
  gap: var(--space-sm);
  justify-content: flex-end;
}
```

7. **Add back link style** (in the form section):
```css
.category-manager-form__back {
  display: inline-flex;
  align-items: center;
  gap: var(--space-xs);
  padding: 0;
  margin-bottom: var(--space-md);
  background: none;
  border: none;
  color: var(--color-accent);
  font-size: 0.9rem;
  cursor: pointer;
  transition: color var(--transition-fast);
}

.category-manager-form__back:hover {
  color: var(--color-accent-hover, var(--color-accent));
  text-decoration: underline;
}
```

- [ ] **Step 2: Run all existing tests to verify nothing is broken**

Run: `cd frontend && npx vitest run tests/CategoryManagerTree.test.tsx tests/CategoryManagerForm.test.tsx tests/QuickCreatePopover.test.tsx`
Expected: All PASS (CSS changes don't affect test behavior but verify nothing else broke)

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/category/CategoryManagerModal.css
git commit -m "style: update CSS for slide track layout, popover, and back link"
```

---

### Task 5: Update CategoryManagerModal — View State + Slide Track + Quick Create

**Files:**
- Modify: `frontend/src/components/category/CategoryManagerModal.tsx`
- Modify: `frontend/tests/CategoryManagerModal.test.tsx`

This is the main orchestrator change. Update the modal to use view state, slide track, and integrate the quick-create popover.

- [ ] **Step 1: Update CategoryManagerModal tests**

In `frontend/tests/CategoryManagerModal.test.tsx`:

1. **Update the mock for CategoryManagerTree** (lines 117-130). Replace `onSelect` with `onEditCategory`:
```tsx
vi.mock('../src/components/category/CategoryManagerTree', () => ({
  default: (props: Record<string, unknown>) => {
    lastTreeProps = props;
    return (
      <div data-testid="category-manager-tree">
        <button data-testid="tree-edit-1" onClick={() => (props.onEditCategory as (id: number) => void)(1)}>Edit 1</button>
        <button data-testid="tree-edit-2" onClick={() => (props.onEditCategory as (id: number) => void)(2)}>Edit 2</button>
        <button data-testid="tree-add" onClick={props.onAdd as () => void}>Add</button>
        <button data-testid="tree-reorder" onClick={() => (props.onReorder as (u: { categoryId: number; sortOrder: number }[]) => void)([{ categoryId: 1, sortOrder: 0 }, { categoryId: 2, sortOrder: 1 }])}>Reorder</button>
        <button data-testid="tree-reparent" onClick={() => (props.onReparent as (id: number, parentId: number | null) => void)(3, 2)}>Reparent</button>
      </div>
    );
  },
}));
```

2. **Update the mock for CategoryManagerForm** (lines 133-151). Add `onBack`, `onDelete`, `onCancel` buttons:
```tsx
vi.mock('../src/components/category/CategoryManagerForm', () => ({
  default: (props: Record<string, unknown>) => {
    lastFormProps = props;
    const formRef = props.formRef as React.RefObject<{ submit: () => void } | null> | undefined;
    if (formRef && 'current' in formRef) {
      (formRef as React.MutableRefObject<{ submit: () => void } | null>).current = {
        submit: () => (props.onSave as (u: { name: string; description: string; parentCategoryId: number | null; itemTemplateIds: number[] }) => void)({ name: 'Updated', description: 'Desc', parentCategoryId: null, itemTemplateIds: [] }),
      };
    }
    return (
      <div data-testid="category-manager-form">
        <button data-testid="form-save" onClick={() => (props.onSave as (u: { name: string; description: string; parentCategoryId: number | null; itemTemplateIds: number[] }) => void)({ name: 'Updated', description: 'Desc', parentCategoryId: null, itemTemplateIds: [] })}>Save</button>
        <button data-testid="form-back" onClick={props.onBack as () => void}>Back</button>
        <button data-testid="form-delete" onClick={props.onDelete as () => void}>Delete Form</button>
        <button data-testid="form-cancel" onClick={props.onCancel as () => void}>Cancel Form</button>
        <button data-testid="form-publish" onClick={() => (props.onPublish as (c: Category) => void)(mockCategories[0])}>Publish</button>
        <button data-testid="form-unpublish" onClick={() => (props.onUnpublish as (c: Category) => void)(mockCategories[2])}>Unpublish</button>
      </div>
    );
  },
}));
```

3. **Add mock for QuickCreatePopover**:
```tsx
let lastPopoverProps: Record<string, unknown> = {};
vi.mock('../src/components/category/QuickCreatePopover', () => ({
  default: (props: Record<string, unknown>) => {
    lastPopoverProps = props;
    if (!props.isVisible) return null;
    return (
      <div data-testid="quick-create-popover">
        <button data-testid="popover-save" onClick={() => (props.onSave as (name: string) => void)('Quick Cat')}>Popover Save</button>
        <button data-testid="popover-more" onClick={() => (props.onMoreDetails as (name: string) => void)('Quick Cat')}>Popover More</button>
        <button data-testid="popover-cancel" onClick={props.onCancel as () => void}>Popover Cancel</button>
      </div>
    );
  },
}));
```

4. **Reset `lastPopoverProps` in `beforeEach`**:
```ts
lastPopoverProps = {};
```

5. **Replace the "selecting a category" describe block** with new view state tests:
```tsx
  describe('view state', () => {
    it('should open to tree view by default (no form slide)', () => {
      render(<CategoryManagerModal {...defaultProps} />);
      const track = document.querySelector('.categoryManager__track');
      expect(track).not.toHaveClass('categoryManager__track--form');
    });

    it('should slide to form view when category row is clicked', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-edit-1'));

      const track = document.querySelector('.categoryManager__track');
      expect(track).toHaveClass('categoryManager__track--form');
      expect((lastFormProps.category as Category)?.categoryId).toBe(1);
      expect(lastFormProps.isNew).toBe(false);
    });

    it('should not auto-select a category on open', () => {
      render(<CategoryManagerModal {...defaultProps} />);
      const track = document.querySelector('.categoryManager__track');
      expect(track).not.toHaveClass('categoryManager__track--form');
    });

    it('should reset to tree view when modal re-opens', async () => {
      const user = userEvent.setup();
      const { rerender } = render(<CategoryManagerModal {...defaultProps} />);

      // Slide to form
      await user.click(screen.getByTestId('tree-edit-1'));
      // Close
      rerender(<CategoryManagerModal {...defaultProps} isOpen={false} />);
      // Re-open
      rerender(<CategoryManagerModal {...defaultProps} isOpen={true} />);

      const track = document.querySelector('.categoryManager__track');
      expect(track).not.toHaveClass('categoryManager__track--form');
    });
  });
```

6. **Replace the "adding a new category" describe block** with quick-create tests:
```tsx
  describe('quick create', () => {
    it('should show quick create popover when add clicked', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-add'));

      expect(screen.getByTestId('quick-create-popover')).toBeInTheDocument();
    });

    it('should create category and stay on tree when popover Save clicked', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-add'));
      await user.click(screen.getByTestId('popover-save'));

      await waitFor(() => {
        expect(mockAddCategory).toHaveBeenCalledWith({
          collectionId: 1,
          name: 'Quick Cat',
          description: '',
          parentCategoryId: null,
          itemTemplateIds: [],
        });
      });
      // Should stay on tree view
      const track = document.querySelector('.categoryManager__track');
      expect(track).not.toHaveClass('categoryManager__track--form');
    });

    it('should slide to form with name when popover More Details clicked', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-add'));
      await user.click(screen.getByTestId('popover-more'));

      const track = document.querySelector('.categoryManager__track');
      expect(track).toHaveClass('categoryManager__track--form');
      expect(lastFormProps.isNew).toBe(true);
      expect(lastFormProps.initialName).toBe('Quick Cat');
    });

    it('should close popover on cancel', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-add'));
      expect(screen.getByTestId('quick-create-popover')).toBeInTheDocument();

      await user.click(screen.getByTestId('popover-cancel'));

      expect(screen.queryByTestId('quick-create-popover')).not.toBeInTheDocument();
    });
  });
```

7. **Update "closing the modal" tests** for the new behavior:
```tsx
  describe('closing the modal', () => {
    it('should call onClose when close button clicked from tree view', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();
      render(<CategoryManagerModal {...defaultProps} onClose={onClose} />);

      await user.click(screen.getByLabelText('Close'));

      expect(onClose).toHaveBeenCalled();
    });

    it('should slide back to tree when close button clicked from form view without changes', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();
      render(<CategoryManagerModal {...defaultProps} onClose={onClose} />);

      // Slide to form
      await user.click(screen.getByTestId('tree-edit-1'));
      // Click close
      await user.click(screen.getByLabelText('Close'));

      // Should NOT close modal, should slide back to tree
      expect(onClose).not.toHaveBeenCalled();
      const track = document.querySelector('.categoryManager__track');
      expect(track).not.toHaveClass('categoryManager__track--form');
    });

    it('should call onClose when native dialog close event fires', () => {
      const onClose = vi.fn();
      render(<CategoryManagerModal {...defaultProps} onClose={onClose} />);

      const dialog = document.querySelector('dialog');
      dialog!.dispatchEvent(new Event('close'));

      expect(onClose).toHaveBeenCalled();
    });

    it('should call onClose when backdrop is clicked from tree view', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();
      render(<CategoryManagerModal {...defaultProps} onClose={onClose} />);

      const dialog = document.querySelector('dialog');
      await user.click(dialog!);

      expect(onClose).toHaveBeenCalled();
    });
  });
```

8. **Update "saving a category" tests** — replace `tree-select-1` with `tree-edit-1`, and verify slide back to tree after save:
```tsx
  describe('saving a category (update)', () => {
    it('should call updateCategory and slide back to tree when saving existing category', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-edit-1'));
      await user.click(screen.getByTestId('form-save'));

      await waitFor(() => {
        expect(mockUpdateCategory).toHaveBeenCalledWith(1, { name: 'Updated', description: 'Desc', parentCategoryId: null, itemTemplateIds: [] });
      });
      await waitFor(() => {
        const track = document.querySelector('.categoryManager__track');
        expect(track).not.toHaveClass('categoryManager__track--form');
      });
    });
  });
```

9. **Update "deleting a category" tests** — use `tree-edit-1` to get to form, then use `form-delete`:
```tsx
  describe('deleting a category', () => {
    it('should show delete confirm and call deleteCategory after confirm', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-edit-1'));
      await user.click(screen.getByTestId('form-delete'));

      // Confirm in the delete confirmation modal
      const confirmButtons = screen.getAllByRole('button', { name: 'Delete' });
      await user.click(confirmButtons[confirmButtons.length - 1]);

      await waitFor(() => {
        expect(mockDeleteCategory).toHaveBeenCalledWith(1);
      });
      // Should slide back to tree
      await waitFor(() => {
        const track = document.querySelector('.categoryManager__track');
        expect(track).not.toHaveClass('categoryManager__track--form');
      });
    });
  });
```

10. **Update "form props" and "tree props" tests** — remove auto-select assertions:
```tsx
  describe('form props', () => {
    it('should pass categories and collectionId to form', async () => {
      const user = userEvent.setup();
      render(<CategoryManagerModal {...defaultProps} />);

      await user.click(screen.getByTestId('tree-edit-1'));

      expect(lastFormProps.categories).toEqual(mockCategories);
      expect(lastFormProps.collectionId).toBe(1);
      expect(lastFormProps.isNew).toBe(false);
      expect((lastFormProps.category as Category)?.categoryId).toBe(1);
    });
  });

  describe('tree props', () => {
    it('should pass categories to tree', () => {
      render(<CategoryManagerModal {...defaultProps} />);

      expect(lastTreeProps.categories).toEqual(mockCategories);
    });
  });
```

11. **Update publish/unpublish tests** — replace `tree-select-1` with `tree-edit-1`.

12. **Update error handling tests** — replace `tree-select-1` with `tree-edit-1`.

13. **Remove the "Cancel button disabled" test** from closing section (footer is now in the form component).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npx vitest run tests/CategoryManagerModal.test.tsx`
Expected: FAIL — component still has old structure

- [ ] **Step 3: Update CategoryManagerModal component**

In `frontend/src/components/category/CategoryManagerModal.tsx`:

1. **Add import for QuickCreatePopover** (after line 8):
```ts
import QuickCreatePopover from './QuickCreatePopover';
```

2. **Add new state variables** (after line 38):
```ts
  const [view, setView] = useState<'tree' | 'form'>('tree');
  const [showQuickCreate, setShowQuickCreate] = useState(false);
  const [initialName, setInitialName] = useState('');
```

3. **Remove the auto-select useEffect** (lines 83-93). Delete this entire block:
```ts
  // Auto-select first category when categories load and nothing is selected
  useEffect(() => { ... });
```

4. **Update the reset effect** (lines 72-81). Add view state reset:
```ts
  useEffect(() => {
    if (isOpen) {
      loadCategoriesForCollection(collectionId);
      /* eslint-disable react-hooks/set-state-in-effect -- Resetting state when modal opens */
      setSelectedCategoryId(null);
      setIsNew(false);
      setFormHasChanges(false);
      setView('tree');
      setShowQuickCreate(false);
      setInitialName('');
      /* eslint-enable react-hooks/set-state-in-effect */
    }
  }, [isOpen, collectionId, loadCategoriesForCollection]);
```

5. **Replace `handleCloseAttempt`** (lines 102-109):
```ts
  const handleCloseAttempt = useCallback(() => {
    if (view === 'tree') {
      onClose();
    } else if (formHasChanges) {
      setPendingNavigation({ type: 'close' });
      setShowCancelConfirm(true);
    } else {
      setView('tree');
      setSelectedCategoryId(null);
    }
  }, [view, formHasChanges, onClose]);
```

6. **Replace `handleSelect` with `handleEditCategory`** (lines 117-126):
```ts
  const handleEditCategory = useCallback((categoryId: number) => {
    setSelectedCategoryId(categoryId);
    setIsNew(false);
    setInitialName('');
    setView('form');
  }, []);
```

7. **Replace `handleAdd` with quick-create handler** (lines 128-136):
```ts
  const handleAdd = useCallback(() => {
    setShowQuickCreate(true);
  }, []);
```

8. **Add quick-create handlers** (after handleAdd):
```ts
  const handleQuickCreateSave = useCallback(async (name: string) => {
    setShowQuickCreate(false);
    try {
      const newId = await addCategory({
        collectionId,
        name,
        description: '',
        parentCategoryId: null,
        itemTemplateIds: [],
      });
      // Move new category to top of root-level sort order
      const rootSiblings = categories.filter(c => c.parentCategoryId === null && !c.isSystem);
      const sortUpdates = [
        { categoryId: newId, sortOrder: 0 },
        ...rootSiblings.map((s, i) => ({ categoryId: s.categoryId, sortOrder: i + 1 })),
      ];
      await reorderCategories(sortUpdates);
      await loadCategoriesForCollection(collectionId);
    } catch (err) {
      console.error('Failed to create category:', err);
    }
  }, [collectionId, categories, addCategory, reorderCategories, loadCategoriesForCollection]);

  const handleQuickCreateMoreDetails = useCallback((name: string) => {
    setShowQuickCreate(false);
    setInitialName(name);
    setSelectedCategoryId(null);
    setIsNew(true);
    setView('form');
  }, []);

  const handleQuickCreateCancel = useCallback(() => {
    setShowQuickCreate(false);
  }, []);
```

9. **Add handleBack** (before handleCancelClick):
```ts
  const handleBack = useCallback(() => {
    if (formHasChanges) {
      setPendingNavigation({ type: 'close' });
      setShowCancelConfirm(true);
    } else {
      setView('tree');
      setSelectedCategoryId(null);
    }
  }, [formHasChanges]);
```

10. **Update `handleCancelClick`** (lines 138-143):
```ts
  const handleCancelClick = useCallback(() => {
    if (formHasChanges) {
      setPendingNavigation(null);
      setShowCancelConfirm(true);
    }
  }, [formHasChanges]);
```

11. **Update `handleDiscardConfirm`** (lines 145-161). Change `close` navigation to slide back instead of closing:
```ts
  const handleDiscardConfirm = useCallback(() => {
    setShowCancelConfirm(false);
    setFormHasChanges(false);
    const nav = pendingNavigation;
    setPendingNavigation(null);

    if (nav?.type === 'close') {
      setView('tree');
      setSelectedCategoryId(null);
    }
    // null pendingNavigation = cancel button clicked, just revert to current category
  }, [pendingNavigation]);
```

12. **Update `handleSave`** (lines 167-187). Add slide back to tree after save:
```ts
  const handleSave = useCallback(async (updates: { name: string; description: string; parentCategoryId: number | null; itemTemplateIds: number[] }) => {
    try {
      if (isNew) {
        await addCategory({
          collectionId,
          name: updates.name,
          description: updates.description,
          parentCategoryId: updates.parentCategoryId,
          itemTemplateIds: updates.itemTemplateIds,
        });
      } else if (selectedCategoryId) {
        await updateCategory(selectedCategoryId, updates);
      }
      await loadCategoriesForCollection(collectionId);
      setView('tree');
      setSelectedCategoryId(null);
      setIsNew(false);
    } catch (err) {
      console.error('Failed to save category:', err);
    }
  }, [isNew, selectedCategoryId, collectionId, addCategory, updateCategory, loadCategoriesForCollection]);
```

13. **Update `handleDeleteConfirm`** (lines 195-209). Slide back to tree:
```ts
  const handleDeleteConfirm = useCallback(async () => {
    if (!selectedCategoryId) return;
    const deletedId = selectedCategoryId;
    setShowDeleteConfirm(false);
    try {
      await deleteCategory(deletedId);
      await loadCategoriesForCollection(collectionId);
      setView('tree');
      setSelectedCategoryId(null);
      setIsNew(false);
      setFormHasChanges(false);
    } catch (err) {
      console.error('Failed to delete category:', err);
    }
  }, [selectedCategoryId, deleteCategory, collectionId, loadCategoriesForCollection]);
```

14. **Update the JSX return** (lines 313-382). Replace the `categoryManager` div with the slide track structure, and remove the footer from modal level:

```tsx
        <div className="categoryManager">
          <div className={`categoryManager__track${view === 'form' ? ' categoryManager__track--form' : ''}`}>
            <div className="categoryManager__tree">
              <CategoryManagerTree
                categories={categories}
                onEditCategory={handleEditCategory}
                onAdd={handleAdd}
                onReorder={handleReorder}
                onReparent={handleReparent}
              />
              {showQuickCreate && (
                <QuickCreatePopover
                  isVisible={showQuickCreate}
                  onSave={handleQuickCreateSave}
                  onMoreDetails={handleQuickCreateMoreDetails}
                  onCancel={handleQuickCreateCancel}
                />
              )}
            </div>
            <div className="categoryManager__form">
              <CategoryManagerForm
                category={selectedCategory}
                categories={categories}
                collectionId={collectionId}
                isNew={isNew}
                initialName={initialName}
                onSave={handleSave}
                onBack={handleBack}
                onDelete={handleDeleteClick}
                onCancel={handleCancelClick}
                onPublish={handlePublish}
                onUnpublish={handleUnpublish}
                onHasChanges={setFormHasChanges}
                formRef={formRef}
              />
            </div>
          </div>
        </div>
```

15. **Remove the footer JSX** (lines 352-381 — the `.categoryManager__footer` div). The footer is now inside CategoryManagerForm.

16. **Remove `handleSaveClick`** (line 163-165). No longer needed since the form handles its own save button via formRef internally.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npx vitest run tests/CategoryManagerModal.test.tsx`
Expected: All tests PASS

- [ ] **Step 5: Run ALL tests to verify nothing is broken**

Run: `cd frontend && npx vitest run`
Expected: All tests PASS across the entire frontend

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/category/CategoryManagerModal.tsx frontend/tests/CategoryManagerModal.test.tsx
git commit -m "feat: implement split UX with slide transitions and quick-create popover"
```

---

### Task 6: Integration Verification

**Files:** None (testing only)

- [ ] **Step 1: Run full frontend test suite**

Run: `cd frontend && npx vitest run`
Expected: All tests PASS

- [ ] **Step 2: Run lint**

Run: `cd frontend && npm run lint`
Expected: No errors

- [ ] **Step 3: Run build**

Run: `cd frontend && npm run build`
Expected: Successful build, no TypeScript errors

- [ ] **Step 4: Commit any lint/build fixes if needed**

If any fixes were required:
```bash
git add -A
git commit -m "fix: resolve lint/build issues from category manager split UX"
```
