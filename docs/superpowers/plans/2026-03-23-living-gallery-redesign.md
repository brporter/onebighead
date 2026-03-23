# Living Gallery Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform OneBigHead's frontend from a generic admin dashboard into a warm, gallery-inspired collection browsing experience with masonry cards, collapsible sidebar, and consistent design tokens.

**Architecture:** The redesign touches three layers: (1) design tokens and global CSS, (2) restyled existing components (header, sidebar, buttons, forms, modals), and (3) new React components (ItemCard, masonry grid container, sidebar collapse). Changes are incremental — each task produces a working state.

**Tech Stack:** React 19, Vite, Vitest, CSS custom properties, Google Fonts (Fraunces, DM Sans)

**Design Spec:** `docs/superpowers/specs/2026-03-23-living-gallery-redesign-design.md`

---

## File Structure

### New Files
| File | Responsibility |
|------|---------------|
| `frontend/src/utils/accentColors.ts` | Category accent color palette + index-based assignment utility |
| `frontend/tests/accentColors.test.ts` | Tests for accent color utility |
| `frontend/src/components/item/ItemCard.tsx` | Adaptive item card (image vs text-only) |
| `frontend/src/components/item/ItemCard.css` | ItemCard styles (masonry cards, ribbons, pills, hover) |
| `frontend/tests/ItemCard.test.tsx` | Tests for ItemCard component |

### Modified Files
| File | Changes |
|------|---------|
| `frontend/index.html` | Add Google Fonts preconnect + stylesheet links |
| `frontend/src/styles/App.css` | Replace :root tokens, remove dark mode block, add typography classes, restyle header/sidebar/buttons/forms/modals, add reduced-motion media query |
| `frontend/src/components/item/ItemList.tsx` | Replace table with masonry grid of ItemCard components |
| `frontend/tests/ItemList.test.tsx` | Update tests for card-based rendering (no more table/tr elements) |
| `frontend/src/components/category/CategoryTree.tsx` | Add accent color dots, replace inline paddingLeft with CSS classes |
| `frontend/tests/CategoryTree.test.tsx` | Update tests for accent dots, update snapshots |
| `frontend/src/views/CategoryView.tsx` | Add sidebar collapse state, pass categories to ItemList for accent colors |
| `frontend/tests/CategoryView.test.tsx` | Add tests for sidebar collapse behavior |

---

## Task 1: Update Design Tokens and Font Imports

**Files:**
- Modify: `frontend/index.html`
- Modify: `frontend/src/styles/App.css:1-128` (tokens + dark mode block)

- [ ] **Step 1: Run all existing tests to establish baseline**

Run: `cd frontend && npm run test:run`
Expected: All tests pass (this is our baseline before any changes)

- [ ] **Step 2: Add Google Font imports to index.html**

Replace `frontend/index.html` content:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,600&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
    <title>OneBigHead - Collection Manager</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 3: Replace :root tokens in App.css**

Replace the entire `:root { ... }` block (from the `/* Colors - Light Mode */` comment through the closing `}` before the dark mode media query) with the new Living Gallery token set per the design spec Section 1:

```css
:root {
  /* Colors - Living Gallery Light Mode */
  --color-bg: #f8f6f3;
  --color-bg-end: #eee8e0;
  --color-surface: #ffffff;
  --color-surface-alt: #f3ede6;
  --color-surface-textonly: #faf7f3;
  --color-surface-textonly-end: #f3ede6;

  --color-border: #e5ddd2;
  --color-border-strong: #d4c4b0;

  --color-text: #3a3028;
  --color-text-secondary: #5a4e42;
  --color-text-body: #7a6e62;
  --color-text-muted: #9a8a78;

  --color-primary: #3a3028;
  --color-primary-hover: #4a3f35;
  --color-primary-text: #f0ebe4;
  --color-accent: #c77d4a;
  --color-accent-subtle: rgba(199, 125, 74, 0.08);

  --color-success: #6b8f71;
  --color-success-hover: #5a7e60;
  --color-success-bg: rgba(107, 143, 113, 0.1);
  --color-success-border: #8baf91;

  --color-warning: #c7944a;
  --color-warning-hover: #b78340;
  --color-warning-bg: rgba(199, 148, 74, 0.1);
  --color-warning-subtle: rgba(199, 148, 74, 0.1);
  --color-warning-border: #d4a574;

  --color-info: #7a8ca8;
  --color-info-hover: #6a7c98;
  --color-info-bg: rgba(122, 140, 168, 0.1);
  --color-info-border: #9aacbf;

  --color-danger: #b85450;
  --color-danger-hover: #a84440;
  --color-danger-bg: rgba(184, 84, 80, 0.1);
  --color-danger-bg-hover: rgba(184, 84, 80, 0.15);
  --color-danger-border: #d4a098;

  /* Shadows & Elevation */
  --shadow-sm: 0 2px 10px rgba(58, 48, 40, 0.05);
  --shadow-md: 0 6px 20px rgba(58, 48, 40, 0.09);
  --shadow-lg: 0 20px 50px rgba(58, 48, 40, 0.25);

  /* Overlays & Backgrounds */
  --overlay-bg: rgba(58, 48, 40, 0.5);
  --header-nav-bg: rgba(255, 255, 255, 0.08);
  --header-nav-bg-muted: rgba(255, 255, 255, 0.04);
  --hover-bg: rgba(0, 0, 0, 0.03);
  --pill-bg: #f5f0ea;

  /* Spacing */
  --space-xs: 0.25rem;
  --space-sm: 0.5rem;
  --space-md: 1rem;
  --space-lg: 1.5rem;
  --space-xl: 2rem;
  --space-xxl: 3rem;

  /* Border Radius */
  --radius-sm: 4px;
  --radius-md: 6px;
  --radius-lg: 8px;

  /* Transitions */
  --transition-fast: 0.15s ease;
}
```

- [ ] **Step 4: Remove the dark mode block**

Delete the entire `@media (prefers-color-scheme: dark) { :root { ... } }` block (the media query with all dark mode token overrides). Per spec: dark mode will be rebuilt from scratch later.

- [ ] **Step 5: Add typography utility classes**

Add after the `:root` block (before any other styles):

```css
/* ==========================================================================
   Typography Utility Classes
   ========================================================================== */

.type-display-lg { font-family: 'Fraunces', serif; font-size: 26px; font-weight: 600; letter-spacing: -0.3px; line-height: 1.2; }
.type-display-md { font-family: 'Fraunces', serif; font-size: 17px; font-weight: 400; letter-spacing: -0.3px; line-height: 1.3; }
.type-display-sm { font-family: 'Fraunces', serif; font-size: 14px; font-weight: 400; letter-spacing: -0.3px; line-height: 1.3; }
.type-display-xs { font-family: 'Fraunces', serif; font-size: 13px; font-weight: 400; letter-spacing: -0.3px; line-height: 1.3; }
.type-body-lg { font-family: 'DM Sans', sans-serif; font-size: 14px; font-weight: 400; line-height: 1.5; }
.type-body { font-family: 'DM Sans', sans-serif; font-size: 13px; font-weight: 400; line-height: 1.5; }
.type-body-sm { font-family: 'DM Sans', sans-serif; font-size: 12px; font-weight: 400; line-height: 1.5; }
.type-caption { font-family: 'DM Sans', sans-serif; font-size: 11px; font-weight: 400; line-height: 1.4; }
.type-label { font-family: 'DM Sans', sans-serif; font-size: 11px; font-weight: 600; letter-spacing: 2px; text-transform: uppercase; }
.type-badge { font-family: 'DM Sans', sans-serif; font-size: 9px; font-weight: 600; letter-spacing: 1.5px; text-transform: uppercase; }

/* ==========================================================================
   Reduced Motion
   ========================================================================== */

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01s !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01s !important;
  }
}
```

- [ ] **Step 6: Update the base body/html styles**

Find the `body` rule in App.css and update the font-family and background:

```css
body {
  font-family: 'DM Sans', sans-serif;
  background: linear-gradient(160deg, var(--color-bg) 0%, var(--color-bg-end) 100%);
  color: var(--color-text);
  min-height: 100vh;
}
```

Also update any `font-family` declaration on `html` or `*` selectors to use `'DM Sans', sans-serif` as the base.

- [ ] **Step 7: Run tests to check for regressions**

Run: `cd frontend && npm run test:run`
Expected: All tests pass. Token changes are CSS-only so no test breakage expected. Snapshot tests may need updating if any test captures inline styles affected by token names.

- [ ] **Step 8: Update snapshots if needed**

Run: `cd frontend && npm run test:run -- --update`
Expected: Snapshots updated, all tests pass.

- [ ] **Step 9: Commit**

```bash
git add frontend/index.html frontend/src/styles/App.css
git commit -m "feat: replace design tokens with Living Gallery palette, add typography classes"
```

---

## Task 2: Category Accent Color Utility

**Files:**
- Create: `frontend/src/utils/accentColors.ts`
- Create: `frontend/tests/accentColors.test.ts`

- [ ] **Step 1: Write failing tests for accent color utility**

Create `frontend/tests/accentColors.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { getAccentColor, DEFAULT_PALETTE } from '../src/utils/accentColors';

describe('getAccentColor', () => {
  it('should return first palette color for index 0', () => {
    const color = getAccentColor(0);
    expect(color).toEqual(DEFAULT_PALETTE[0]);
  });

  it('should return second palette color for index 1', () => {
    const color = getAccentColor(1);
    expect(color).toEqual(DEFAULT_PALETTE[1]);
  });

  it('should cycle through palette when index exceeds palette length', () => {
    const color = getAccentColor(DEFAULT_PALETTE.length);
    expect(color).toEqual(DEFAULT_PALETTE[0]);
  });

  it('should cycle correctly for large indices', () => {
    const color = getAccentColor(DEFAULT_PALETTE.length + 3);
    expect(color).toEqual(DEFAULT_PALETTE[3]);
  });

  it('should handle index 0 with custom palette', () => {
    const custom = [{ start: '#aaa', end: '#bbb', name: 'Test' }];
    const color = getAccentColor(0, custom);
    expect(color).toEqual(custom[0]);
  });

  it('should return gradient CSS string from color', () => {
    const color = getAccentColor(0);
    expect(color.start).toBe('#c77d4a');
    expect(color.end).toBe('#d4a574');
    expect(color.name).toBe('Warm copper');
  });
});

describe('DEFAULT_PALETTE', () => {
  it('should have 8 colors', () => {
    expect(DEFAULT_PALETTE).toHaveLength(8);
  });

  it('should have start, end, and name for each color', () => {
    for (const color of DEFAULT_PALETTE) {
      expect(color).toHaveProperty('start');
      expect(color).toHaveProperty('end');
      expect(color).toHaveProperty('name');
      expect(color.start).toMatch(/^#[0-9a-f]{6}$/);
      expect(color.end).toMatch(/^#[0-9a-f]{6}$/);
    }
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npx vitest run tests/accentColors.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Implement accent color utility**

Create `frontend/src/utils/accentColors.ts`:

```typescript
export interface AccentColor {
  start: string;
  end: string;
  name: string;
}

export const DEFAULT_PALETTE: AccentColor[] = [
  { start: '#c77d4a', end: '#d4a574', name: 'Warm copper' },
  { start: '#6b8f71', end: '#8baf91', name: 'Sage green' },
  { start: '#7a8ca8', end: '#9aacbf', name: 'Dusty blue' },
  { start: '#b8926a', end: '#c8a67e', name: 'Golden tan' },
  { start: '#9a7ea8', end: '#b098be', name: 'Muted plum' },
  { start: '#a88c7e', end: '#b8a090', name: 'Warm taupe' },
  { start: '#8a9a6b', end: '#a0b085', name: 'Olive' },
  { start: '#c4847a', end: '#d4a098', name: 'Dusty rose' },
];

export function getAccentColor(index: number, palette: AccentColor[] = DEFAULT_PALETTE): AccentColor {
  return palette[index % palette.length];
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npx vitest run tests/accentColors.test.ts`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/utils/accentColors.ts frontend/tests/accentColors.test.ts
git commit -m "feat: add category accent color palette utility"
```

---

## Task 3: Build ItemCard Component

**Files:**
- Create: `frontend/src/components/item/ItemCard.tsx`
- Create: `frontend/src/components/item/ItemCard.css`
- Create: `frontend/tests/ItemCard.test.tsx`

- [ ] **Step 1: Write failing tests for ItemCard**

Create `frontend/tests/ItemCard.test.tsx`:

```tsx
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ItemCard from '../src/components/item/ItemCard';
import type { Item } from '../src/utils/types';
import { Visibility, UserFlag } from '../src/utils/types';
import type { AccentColor } from '../src/utils/accentColors';

describe('ItemCard', () => {
  const defaultAccent: AccentColor = { start: '#c77d4a', end: '#d4a574', name: 'Warm copper' };

  const itemWithImages: Item = {
    id: 1,
    workspaceId: 1,
    collectionId: 1,
    categoryId: 1,
    templateKey: null,
    name: 'Leica M3',
    summary: 'Classic rangefinder',
    description: 'A pristine example',
    properties: [
      { category: 'Details', name: 'Year', value: '1956' },
      { category: 'Details', name: 'Condition', value: 'Excellent' },
    ],
    images: [{ url: '/images/leica.jpg', alt: 'Leica M3' }],
    visibility: Visibility.Default,
    effectiveIsPublic: false,
    userFlag: UserFlag.Have,
  };

  const itemWithoutImages: Item = {
    id: 2,
    workspaceId: 1,
    collectionId: 1,
    categoryId: 1,
    templateKey: null,
    name: 'Nikon FM2',
    summary: 'Mechanical workhorse',
    description: 'Titanium shutter',
    properties: [
      { category: 'Details', name: 'Year', value: '1982' },
    ],
    images: [],
    visibility: Visibility.Default,
    effectiveIsPublic: false,
    userFlag: UserFlag.Have,
  };

  const defaultProps = {
    item: itemWithImages,
    accentColor: defaultAccent,
    isSelected: false,
    onSelect: vi.fn(),
  };

  describe('snapshots', () => {
    it('should render image card', () => {
      const { container } = render(<ItemCard {...defaultProps} />);
      expect(container).toMatchSnapshot();
    });

    it('should render text-only card', () => {
      const { container } = render(<ItemCard {...defaultProps} item={itemWithoutImages} />);
      expect(container).toMatchSnapshot();
    });

    it('should render selected card', () => {
      const { container } = render(<ItemCard {...defaultProps} isSelected={true} />);
      expect(container).toMatchSnapshot();
    });
  });

  describe('image card rendering', () => {
    it('should render item name', () => {
      render(<ItemCard {...defaultProps} />);
      expect(screen.getByText('Leica M3')).toBeInTheDocument();
    });

    it('should render item summary as metadata', () => {
      render(<ItemCard {...defaultProps} />);
      expect(screen.getByText('Classic rangefinder')).toBeInTheDocument();
    });

    it('should render item image', () => {
      render(<ItemCard {...defaultProps} />);
      const img = screen.getByAltText('Leica M3');
      expect(img).toBeInTheDocument();
      expect(img).toHaveAttribute('src', '/images/leica.jpg');
    });

    it('should render accent ribbon with gradient', () => {
      const { container } = render(<ItemCard {...defaultProps} />);
      const ribbon = container.querySelector('.item-card__ribbon');
      expect(ribbon).toBeInTheDocument();
      expect(ribbon).toHaveStyle({ background: 'linear-gradient(90deg, #c77d4a, #d4a574)' });
    });
  });

  describe('text-only card rendering', () => {
    it('should have text-only modifier class when no images', () => {
      const { container } = render(<ItemCard {...defaultProps} item={itemWithoutImages} />);
      expect(container.querySelector('.item-card--textonly')).toBeInTheDocument();
    });

    it('should not have text-only modifier when images exist', () => {
      const { container } = render(<ItemCard {...defaultProps} />);
      expect(container.querySelector('.item-card--textonly')).not.toBeInTheDocument();
    });

    it('should render summary text on text-only cards', () => {
      render(<ItemCard {...defaultProps} item={itemWithoutImages} />);
      expect(screen.getByText('Mechanical workhorse')).toBeInTheDocument();
    });

    it('should render property pills on text-only cards', () => {
      render(<ItemCard {...defaultProps} item={itemWithoutImages} />);
      expect(screen.getByText('1982')).toBeInTheDocument();
    });
  });

  describe('interaction', () => {
    it('should call onSelect when clicked', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(<ItemCard {...defaultProps} onSelect={handleSelect} />);

      await user.click(screen.getByRole('button', { name: /Leica M3/ }));
      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('should call onSelect on Enter key', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(<ItemCard {...defaultProps} onSelect={handleSelect} />);

      const card = screen.getByRole('button', { name: /Leica M3/ });
      card.focus();
      await user.keyboard('{Enter}');
      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('should call onSelect on Space key', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      render(<ItemCard {...defaultProps} onSelect={handleSelect} />);

      const card = screen.getByRole('button', { name: /Leica M3/ });
      card.focus();
      await user.keyboard(' ');
      expect(handleSelect).toHaveBeenCalledWith(1);
    });

    it('should not call onSelect for item with null id', async () => {
      const user = userEvent.setup();
      const handleSelect = vi.fn();
      const nullIdItem = { ...itemWithImages, id: null, name: 'Null item' };
      render(<ItemCard {...defaultProps} item={nullIdItem} onSelect={handleSelect} />);

      await user.click(screen.getByRole('button', { name: /Null item/ }));
      expect(handleSelect).not.toHaveBeenCalled();
    });

    it('should have selected class when isSelected is true', () => {
      const { container } = render(<ItemCard {...defaultProps} isSelected={true} />);
      expect(container.querySelector('.item-card--selected')).toBeInTheDocument();
    });
  });

  describe('property pills', () => {
    it('should show max 3 property pills then overflow count on text-only cards', () => {
      const manyProps: Item = {
        ...itemWithoutImages,
        properties: [
          { category: 'A', name: 'P1', value: 'V1' },
          { category: 'A', name: 'P2', value: 'V2' },
          { category: 'A', name: 'P3', value: 'V3' },
          { category: 'A', name: 'P4', value: 'V4' },
          { category: 'A', name: 'P5', value: 'V5' },
          { category: 'A', name: 'P6', value: 'V6' },
        ],
      };
      render(<ItemCard {...defaultProps} item={manyProps} />);
      expect(screen.getByText('+3 more')).toBeInTheDocument();
    });

    it('should not show pills section on image cards', () => {
      const { container } = render(<ItemCard {...defaultProps} />);
      expect(container.querySelector('.item-card__props')).not.toBeInTheDocument();
    });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npx vitest run tests/ItemCard.test.tsx`
Expected: FAIL — module not found

- [ ] **Step 3: Implement ItemCard component**

Create `frontend/src/components/item/ItemCard.tsx`:

```tsx
import type { Item } from '../../utils/types';
import type { AccentColor } from '../../utils/accentColors';
import type { KeyboardEvent } from 'react';
import './ItemCard.css';

const MAX_PILLS = 3;

interface ItemCardProps {
  item: Item;
  accentColor: AccentColor;
  isSelected: boolean;
  onSelect: (id: number) => void;
}

function ItemCard({ item, accentColor, isSelected, onSelect }: ItemCardProps) {
  const hasImages = item.images.length > 0;
  const isTextOnly = !hasImages;

  function handleClick() {
    if (item.id !== null) {
      onSelect(item.id);
    }
  }

  function handleKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      if (item.id !== null) {
        onSelect(item.id);
      }
    }
  }

  const visibleProps = item.properties.slice(0, MAX_PILLS);
  const extraCount = item.properties.length - MAX_PILLS;

  return (
    <div
      className={`item-card${isTextOnly ? ' item-card--textonly' : ''}${isSelected ? ' item-card--selected' : ''}`}
      role="button"
      tabIndex={0}
      aria-label={`Select ${item.name}`}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
    >
      <div
        className="item-card__ribbon"
        style={{ background: `linear-gradient(90deg, ${accentColor.start}, ${accentColor.end})` }}
      />

      {hasImages && (
        <img
          className="item-card__img"
          src={item.images[0].url}
          alt={item.images[0].alt || item.name}
          loading="lazy"
        />
      )}

      <div className="item-card__body">
        <div className="item-card__name">{item.name}</div>
        {item.summary && (
          <div className="item-card__meta">{item.summary}</div>
        )}

        {isTextOnly && item.properties.length > 0 && (
          <div className="item-card__props">
            {visibleProps.map((prop) => (
              <span key={`${prop.category}-${prop.name}`} className="item-card__prop">
                {prop.value}
              </span>
            ))}
            {extraCount > 0 && (
              <span className="item-card__prop">+{extraCount} more</span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default ItemCard;
```

- [ ] **Step 4: Create ItemCard CSS**

Create `frontend/src/components/item/ItemCard.css`:

```css
.item-card {
  background: var(--color-surface);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  overflow: hidden;
  cursor: pointer;
  transition: transform var(--transition-fast), box-shadow var(--transition-fast);
  break-inside: avoid;
  margin-bottom: 14px;
}

.item-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}

.item-card:focus-visible {
  outline: 2px solid var(--color-accent);
  outline-offset: 2px;
}

.item-card--selected {
  outline: 2px solid var(--color-accent);
  outline-offset: 0;
}

/* Text-only variant */
.item-card--textonly {
  background: linear-gradient(135deg, var(--color-surface-textonly), var(--color-surface-textonly-end));
  border: 1px solid var(--color-border);
}

/* Ribbon */
.item-card__ribbon {
  height: 4px;
}

/* Image */
.item-card__img {
  width: 100%;
  display: block;
  object-fit: cover;
}

/* Body */
.item-card__body {
  padding: 14px 16px;
}

.item-card__name {
  font-family: 'Fraunces', serif;
  font-size: 14px;
  color: var(--color-text);
  line-height: 1.3;
}

.item-card--textonly .item-card__name {
  font-size: 15px;
}

.item-card__meta {
  font-family: 'DM Sans', sans-serif;
  font-size: 11px;
  color: var(--color-text-muted);
  margin-top: 4px;
}

/* Property pills (text-only cards) */
.item-card__props {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  margin-top: 8px;
}

.item-card__prop {
  font-family: 'DM Sans', sans-serif;
  font-size: 10px;
  padding: 3px 8px;
  border-radius: 10px;
  background: var(--pill-bg);
  color: var(--color-text-muted);
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd frontend && npx vitest run tests/ItemCard.test.tsx`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/item/ItemCard.tsx frontend/src/components/item/ItemCard.css frontend/tests/ItemCard.test.tsx
git commit -m "feat: add ItemCard component with adaptive image/text-only rendering"
```

---

## Task 4: Convert ItemList from Table to Masonry Grid

**Files:**
- Modify: `frontend/src/components/item/ItemList.tsx`
- Modify: `frontend/tests/ItemList.test.tsx`
- Modify: `frontend/src/styles/App.css` (item list section)

- [ ] **Step 1: Update ItemList tests for card-based rendering**

Rewrite `frontend/tests/ItemList.test.tsx`. Key changes:
- Replace all `getByRole('button', { name: 'Select ...' })` on `<tr>` with card-based queries
- Remove references to `list__tr`, `list__tr--active`, table elements
- Add `categories` prop to defaultProps
- Tests should query by item name text or aria-label instead of table structure

**Important:** Update ALL render calls in the test file, not just `defaultProps`. The existing file has inline renders (e.g., snapshot tests at lines 37-46) that pass props directly without spreading `defaultProps` — these all need the new required `categories` prop added too.

The tests should verify the same behaviors (selection, pagination, add button, keyboard nav, empty state) but against the new card structure. Keep the same test descriptions but update assertions. For example:

```tsx
// OLD: expects table row
// expect(selectedRow).toHaveClass('list__tr--active');

// NEW: expects card
// const card = screen.getByRole('button', { name: 'Select Item 2' });
// expect(card).toHaveClass('item-card--selected');
```

Add `categories` to the default props (needed for accent colors):

```tsx
import type { Category } from '../src/utils/types';

const defaultCategories: Category[] = [{
  workspaceId: 1,
  collectionId: 1,
  categoryId: 1,
  name: 'Test Category',
  description: '',
  parentCategoryId: null,
  isSystem: false,
  visibility: Visibility.Default,
  effectiveIsPublic: false,
  itemTemplateIds: [],
}];

const defaultProps = {
  items: createMockItems(3),
  categories: defaultCategories,
  selectedId: null,
  onSelect: vi.fn(),
  pageIndex: 0,
  onPageChange: vi.fn(),
};
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npx vitest run tests/ItemList.test.tsx`
Expected: FAIL — tests reference new structure that doesn't exist yet

- [ ] **Step 3: Rewrite ItemList component**

Replace `frontend/src/components/item/ItemList.tsx`:

```tsx
import type { Item, Category } from '../../utils/types';
import type { KeyboardEvent } from 'react';
import ItemCard from './ItemCard';
import { getAccentColor } from '../../utils/accentColors';

const PAGE_SIZE = 25;

interface ItemListProps {
  items: Item[];
  categories: Category[];
  selectedId: number | null;
  onSelect: (id: number) => void;
  onAddItem?: (() => void) | null;
  pageIndex: number;
  onPageChange: (pageIndex: number) => void;
}

function ItemList({ items, categories, selectedId, onSelect, onAddItem, pageIndex, onPageChange }: ItemListProps) {
  const totalCount = items.length;
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
  const safePageIndex = Math.min(Math.max(0, pageIndex), totalPages - 1);
  const start = safePageIndex * PAGE_SIZE;
  const pageItems = items.slice(start, start + PAGE_SIZE);

  const canPrev = safePageIndex > 0;
  const canNext = safePageIndex < totalPages - 1;

  // Build category index map for accent colors
  const categoryColorIndex = new Map<number, number>();
  categories.forEach((cat, index) => {
    categoryColorIndex.set(cat.categoryId, index);
  });

  function getItemAccentColor(item: Item) {
    const catIndex = item.categoryId !== null ? (categoryColorIndex.get(item.categoryId) ?? 0) : 0;
    return getAccentColor(catIndex);
  }

  return (
    <aside className="list">
      <div className="list__header">
        <h2 className="list__title">Items</h2>
        <div className="list__headerRight">
          <div className="list__count" aria-label="Item count">
            {totalCount} total
          </div>
          {onAddItem && (
            <button
              type="button"
              className="list__addButton"
              onClick={onAddItem}
            >
              + Add Item
            </button>
          )}
        </div>
      </div>

      <div className="list__masonry">
        {pageItems.length ? (
          pageItems.map((item) => (
            <ItemCard
              key={item.id ?? `new-${item.name}`}
              item={item}
              accentColor={getItemAccentColor(item)}
              isSelected={item.id === selectedId}
              onSelect={onSelect}
            />
          ))
        ) : (
          <p className="list__empty">No items</p>
        )}
      </div>

      <div className="list__pager" aria-label="Pagination">
        <button
          type="button"
          className="list__pagerButton"
          onClick={() => onPageChange(safePageIndex - 1)}
          disabled={!canPrev}
        >
          Previous
        </button>
        <div className="list__pagerStatus">
          Page {safePageIndex + 1} of {totalPages}
        </div>
        <button
          type="button"
          className="list__pagerButton"
          onClick={() => onPageChange(safePageIndex + 1)}
          disabled={!canNext}
        >
          Next
        </button>
      </div>
    </aside>
  );
}

export default ItemList;
```

- [ ] **Step 4: Add masonry CSS to App.css**

In the item list styles section of App.css, replace the `.list__tableWrap` and `.list__table` rules with masonry grid:

```css
.list__masonry {
  columns: 3;
  column-gap: 14px;
  padding: var(--space-md);
}

@media (max-width: 1024px) {
  .list__masonry {
    columns: 2;
  }
}

@media (max-width: 768px) {
  .list__masonry {
    columns: 1;
  }
}
```

Remove the old `.list__table`, `.list__th`, `.list__tr`, `.list__td` rules since the table is gone.

- [ ] **Step 5: Update CategoryView to pass categories to ItemList**

In `frontend/src/views/CategoryView.tsx`, add `categories` prop to the ItemList render (line ~281-288):

```tsx
<ItemList
  items={filteredItems}
  categories={categories}
  selectedId={null}
  onSelect={handleSelectItem}
  onAddItem={handleAddItem}
  pageIndex={safePageIndex}
  onPageChange={handlePageChange}
/>
```

- [ ] **Step 6: Run all tests**

Run: `cd frontend && npm run test:run`
Expected: All tests pass. If snapshot tests fail, update them.

- [ ] **Step 7: Update snapshots if needed**

Run: `cd frontend && npm run test:run -- --update`

- [ ] **Step 8: Commit**

```bash
git add frontend/src/components/item/ItemList.tsx frontend/tests/ItemList.test.tsx frontend/src/styles/App.css frontend/src/views/CategoryView.tsx
git commit -m "feat: convert ItemList from table to masonry grid with ItemCards"
```

---

## Task 5: Restyle Header

**Files:**
- Modify: `frontend/src/styles/App.css` (site-header section)

- [ ] **Step 1: Update header styles in App.css**

Find the `.site-header` rules and update them per the design spec Section 4 (Header):

```css
.site-header {
  position: sticky;
  top: 0;
  z-index: 100;
  background: var(--color-primary);
  color: var(--color-primary-text);
  height: 58px;
}

.site-header__content {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 var(--space-lg);
  height: 100%;
  max-width: 100%;
}

.site-header__brand {
  display: flex;
  align-items: center;
  gap: var(--space-md);
}

.site-header__logo {
  font-family: 'Fraunces', serif;
  font-size: 18px;
  font-weight: 600;
  color: var(--color-primary-text);
  text-decoration: none;
  letter-spacing: -0.3px;
}

.site-header__logo:hover {
  color: var(--color-primary-text);
  opacity: 0.9;
}

.site-header__title {
  font-family: 'DM Sans', sans-serif;
  font-size: 11px;
  padding: 5px 14px;
  border-radius: 20px;
  background: var(--header-nav-bg);
  color: var(--color-text-muted);
  letter-spacing: 0.3px;
  font-weight: 400;
}

.site-header__actions {
  display: flex;
  align-items: center;
  gap: var(--space-md);
}
```

- [ ] **Step 2: Run tests**

Run: `cd frontend && npm run test:run`
Expected: All tests pass. Header changes are CSS-only.

- [ ] **Step 3: Update snapshots if needed**

Run: `cd frontend && npm run test:run -- --update`

- [ ] **Step 4: Commit**

```bash
git add frontend/src/styles/App.css
git commit -m "feat: restyle header with Living Gallery dark warm palette"
```

---

## Task 6: Restyle Category Tree with Accent Dots

**Files:**
- Modify: `frontend/src/components/category/CategoryTree.tsx`
- Modify: `frontend/tests/CategoryTree.test.tsx`
- Modify: `frontend/src/styles/App.css` (categoryTree section)

- [ ] **Step 1: Update CategoryTree tests**

Add tests to `frontend/tests/CategoryTree.test.tsx` for:
- Accent color dots rendering next to each category name
- Dots use the correct accent color based on category index
- Replace inline paddingLeft assertions with CSS class checks

Add new test cases:

```tsx
it('should render accent color dot for each category', () => {
  // render CategoryTree with mock categories
  const dots = container.querySelectorAll('.categoryTree__dot');
  expect(dots.length).toBeGreaterThan(0);
});
```

- [ ] **Step 2: Run tests to verify new tests fail**

Run: `cd frontend && npx vitest run tests/CategoryTree.test.tsx`
Expected: New dot tests fail

- [ ] **Step 3: Update CategoryNodeComponent to add accent dots**

In `frontend/src/components/category/CategoryTree.tsx`, update the CategoryNodeProps to accept `colorIndex`:

```tsx
interface CategoryNodeProps {
  node: CategoryNode;
  level: number;
  selectedCategoryId: number | null;
  onSelect: (categoryId: number) => void;
  expandedIds: Set<number>;
  onToggle: (categoryId: number) => void;
  onEdit: (category: Category) => void;
  colorIndex: number;
}
```

In the CategoryNodeComponent, add the accent dot before the name button. Replace the inline `paddingLeft` with a CSS class approach:

```tsx
import { getAccentColor } from '../../utils/accentColors';

// Inside the component:
const accent = getAccentColor(colorIndex);

// In the JSX, add before the name button:
<span
  className="categoryTree__dot"
  style={{ backgroundColor: accent.start }}
  aria-hidden="true"
/>
```

Replace `style={{ paddingLeft: \`${level * 14}px\` }}` with `className` that uses `--indent-level` CSS custom property:

```tsx
<div className="categoryTree__row" style={{ '--indent-level': level } as React.CSSProperties}>
```

In the tree rendering, pass `colorIndex` based on the category's position:

```tsx
{tree.map((node, index) => (
  <CategoryNodeComponent
    key={node.categoryId}
    node={node}
    level={0}
    colorIndex={index}
    // ... other props
  />
))}
```

For child nodes, pass `colorIndex` from the parent (children inherit their parent's color).

- [ ] **Step 4: Update categoryTree CSS in App.css**

```css
.categoryTree__row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 18px;
  padding-left: calc(18px + var(--indent-level, 0) * 22px);
}

.categoryTree__dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.categoryTree__item--active {
  background: var(--color-accent-subtle);
  color: var(--color-text);
  font-weight: 500;
  border-right: 3px solid var(--color-accent);
}

.categoryTree__item:hover {
  background: var(--hover-bg);
}
```

Update the sidebar background:

```css
.categoryTree {
  background: var(--color-surface-alt);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
}

.categoryTree__title {
  font-family: 'DM Sans', sans-serif;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--color-text-muted);
}
```

- [ ] **Step 5: Run all tests**

Run: `cd frontend && npm run test:run`
Expected: All tests pass

- [ ] **Step 6: Update snapshots if needed**

Run: `cd frontend && npm run test:run -- --update`

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/category/CategoryTree.tsx frontend/tests/CategoryTree.test.tsx frontend/src/styles/App.css
git commit -m "feat: add accent color dots to category tree, restyle sidebar"
```

---

## Task 7: Add Sidebar Collapse Functionality

**Files:**
- Modify: `frontend/src/views/CategoryView.tsx`
- Modify: `frontend/src/styles/App.css` (sidebar + layout)

- [ ] **Step 1: Add sidebar collapse state to CategoryView**

In `frontend/src/views/CategoryView.tsx`, add collapse state:

```tsx
const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

// Determine initial state from viewport width
useEffect(() => {
  const mq = window.matchMedia('(max-width: 1024px)');
  setSidebarCollapsed(mq.matches);
}, []);
```

Update the layout div to include collapse state:

```tsx
<div className={`app__layout${sidebarCollapsed ? ' app__layout--sidebar-collapsed' : ''}`}>
  <nav className="app__sidebar" aria-label="Category navigation">
    <button
      type="button"
      className="app__sidebar-toggle"
      onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
      aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
    >
      {sidebarCollapsed ? '▶' : '◀'}
    </button>
    {!sidebarCollapsed && (
      <CategoryTree
        categories={categories}
        selectedCategoryId={categoryIdNum}
        onSelect={handleSelectCategory}
      />
    )}
  </nav>
```

Do this for both render branches (with and without categoryIdNum).

- [ ] **Step 2: Add collapse CSS**

Add to App.css:

```css
.app__layout--sidebar-collapsed .app__sidebar {
  width: 48px;
  min-width: 48px;
}

.app__layout--sidebar-collapsed {
  grid-template-columns: 48px 1fr;
}

.app__sidebar {
  transition: width 0.2s ease, min-width 0.2s ease;
}

.app__sidebar-toggle {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: var(--radius-sm);
  background: var(--hover-bg);
  border: none;
  color: var(--color-text-muted);
  font-size: 12px;
  cursor: pointer;
  margin: var(--space-sm) auto;
}

.app__sidebar-toggle:hover {
  background: var(--color-border);
}

@media (max-width: 768px) {
  .app__sidebar {
    display: none;
  }

  .app__layout--sidebar-collapsed .app__sidebar {
    display: none;
  }
}
```

- [ ] **Step 3: Add tests for sidebar collapse behavior**

Add test cases to the CategoryView test file (or create one if none exists) covering:

```tsx
it('should render sidebar toggle button', () => {
  // Render CategoryView with route context
  expect(screen.getByLabelText('Collapse sidebar')).toBeInTheDocument();
});

it('should hide CategoryTree when sidebar is collapsed', async () => {
  const user = userEvent.setup();
  // Click toggle to collapse
  await user.click(screen.getByLabelText('Collapse sidebar'));
  // CategoryTree should not be rendered
  expect(screen.queryByText('Categories')).not.toBeInTheDocument();
  // Toggle label should change
  expect(screen.getByLabelText('Expand sidebar')).toBeInTheDocument();
});

it('should show CategoryTree when sidebar is expanded', async () => {
  const user = userEvent.setup();
  // Collapse then expand
  await user.click(screen.getByLabelText('Collapse sidebar'));
  await user.click(screen.getByLabelText('Expand sidebar'));
  expect(screen.getByText('Categories')).toBeInTheDocument();
});

it('should start collapsed on narrow viewports', () => {
  // Mock matchMedia to return matches: true for max-width: 1024px
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: query.includes('max-width: 1024px'),
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
  // Re-render, verify collapsed state
});
```

- [ ] **Step 4: Run all tests**

Run: `cd frontend && npm run test:run`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add frontend/src/views/CategoryView.tsx frontend/src/styles/App.css frontend/tests/CategoryView.test.tsx
git commit -m "feat: add collapsible sidebar with toggle button"
```

---

## Task 8: Restyle Buttons, Forms, and Modals

**Files:**
- Modify: `frontend/src/styles/App.css` (button, form, modal sections)

- [ ] **Step 1: Update button styles**

Find all `.btn` rules and update per spec Section 4 (Buttons):

```css
.btn {
  font-family: 'DM Sans', sans-serif;
  font-size: 12px;
  padding: 7px 16px;
  border-radius: var(--radius-md);
  border: 1px solid transparent;
  cursor: pointer;
  transition: background var(--transition-fast), border-color var(--transition-fast);
  height: 36px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.btn:focus-visible {
  outline: 2px solid var(--color-accent);
  outline-offset: 2px;
}

.btn--primary {
  background: var(--color-primary);
  color: var(--color-primary-text);
  border-color: var(--color-primary);
}

.btn--primary:hover {
  background: var(--color-primary-hover);
}

.btn--secondary {
  background: var(--color-surface);
  color: var(--color-text-secondary);
  border-color: var(--color-border-strong);
}

.btn--danger {
  background: transparent;
  color: var(--color-danger);
  border-color: var(--color-danger);
}

.btn--ghost {
  background: transparent;
  color: var(--color-text-secondary);
  border: none;
}
```

- [ ] **Step 2: Update form input styles**

Find `.detail__input`, `.modal__input`, etc. and update:

```css
input[type="text"],
input[type="email"],
input[type="password"],
input[type="number"],
input[type="url"],
textarea,
select {
  font-family: 'DM Sans', sans-serif;
  font-size: 13px;
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-md);
  background: var(--color-surface);
  color: var(--color-text);
  padding: var(--space-sm) var(--space-md);
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
}

input:focus,
textarea:focus,
select:focus {
  border-color: var(--color-accent);
  box-shadow: 0 0 0 2px rgba(199, 125, 74, 0.15);
  outline: none;
}
```

- [ ] **Step 3: Update modal styles**

Find `.modal-overlay` and `.modal` rules and update:

```css
.modal-overlay {
  background: var(--overlay-bg);
}

.modal {
  background: var(--color-surface);
  border-radius: 10px;
  box-shadow: var(--shadow-lg);
}

.modal__header {
  border-bottom: 1px solid var(--color-border);
}

.modal__title {
  font-family: 'Fraunces', serif;
}
```

- [ ] **Step 4: Run all tests**

Run: `cd frontend && npm run test:run`
Expected: All tests pass

- [ ] **Step 5: Update snapshots if needed**

Run: `cd frontend && npm run test:run -- --update`

- [ ] **Step 6: Commit**

```bash
git add frontend/src/styles/App.css
git commit -m "feat: restyle buttons, forms, and modals with Living Gallery palette"
```

---

## Task 9: Eliminate Hardcoded Values and Clean Up

**Files:**
- Modify: `frontend/src/styles/App.css` (multiple sections)
- Modify: `frontend/src/components/category/CategoryTree.tsx` (inline styles)
- Modify: `frontend/src/components/common/Loading.tsx` (inline styles if any)

- [ ] **Step 1: Search for hardcoded color values in CSS**

Search App.css for any remaining hardcoded hex colors, rgba values, or `#` colors not in `:root`. Replace each with the appropriate token.

Common replacements:
- `#666`, `#999` → `var(--color-text-muted)`
- `#fff` → `var(--color-surface)` or `var(--color-primary-text)` depending on context
- `rgba(0, 0, 0, 0.05)` → `var(--hover-bg)` or `var(--shadow-sm)`
- `rgba(0, 0, 0, 0.5)` → `var(--overlay-bg)`

- [ ] **Step 2: Search for hardcoded spacing values**

Search for `margin` and `padding` values using raw `rem` or `px` values instead of `var(--space-*)`. Replace with the nearest token.

- [ ] **Step 3: Search for inline styles in components**

Use grep to find `style={{` in all .tsx files under `src/components/`. Replace with CSS classes where possible. Some exceptions are OK (e.g., dynamic accent color backgrounds).

- [ ] **Step 4: Remove undefined CSS variable references**

Search for `var(--shadow-lg)`, `var(--color-hover)` etc. that were undefined before this redesign. They should now either be defined (shadow tokens) or replaced.

- [ ] **Step 5: Run all tests**

Run: `cd frontend && npm run test:run`
Expected: All tests pass

- [ ] **Step 6: Run full coverage check**

Run: `cd frontend && npm run test:coverage`
Expected: Coverage meets thresholds (99% statements, 90% branches, 100% functions, 100% lines)

- [ ] **Step 7: Commit**

```bash
git add frontend/src/styles/App.css frontend/src/components/
git commit -m "fix: eliminate all hardcoded colors, spacing, and inline styles"
```

---

## Task 10: Final Responsive Testing and Polish

**Files:**
- Modify: `frontend/src/styles/App.css` (responsive tweaks)

- [ ] **Step 1: Verify responsive breakpoints**

Check all `@media` queries in App.css match the spec:
- Desktop: > 1024px (3-column masonry, expanded sidebar)
- Tablet: 768-1024px (2-column masonry, collapsed sidebar)
- Mobile: < 768px (1-column masonry, no sidebar)

- [ ] **Step 2: Verify reduced-motion media query works**

Confirm the `@media (prefers-reduced-motion: reduce)` block is present and covers all animations.

- [ ] **Step 3: Run full test suite**

Run: `cd frontend && npm run test:run`
Expected: All tests pass

- [ ] **Step 4: Run lint**

Run: `cd frontend && npm run lint`
Expected: No errors

- [ ] **Step 5: Run production build**

Run: `cd frontend && npm run build`
Expected: Build succeeds with no errors

- [ ] **Step 6: Final commit**

```bash
git add frontend/src/styles/App.css
git commit -m "feat: Living Gallery redesign complete — responsive polish and final cleanup"
```
