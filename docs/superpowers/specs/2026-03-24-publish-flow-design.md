# Publish Flow: Simplified Visibility UX

**Date:** 2026-03-24
**Status:** Draft

## Problem

The current visibility model requires users to enable public access at four levels (workspace → collection → category → item) before anything becomes publicly visible. This is cumbersome, confusing, and discourages users from sharing their collections.

## Solution: The Publish Flow

Reframe visibility from "configure permission flags at every level" to "publish items to your gallery." A single publish action on any entity handles the entire chain automatically.

## Mental Model

- **Publish** = "I want this visible in my public gallery"
- **Private** = "This stays in my personal collection"
- The system handles all parent promotion automatically
- Items remember their publish intent even when a parent is unpublished

---

## Data Model Changes

### Visibility Enum

Remove `Default` (inherit). Only two states remain:

- `Public` — user intends this to be publicly visible
- `Private` — user intends this to stay private

**Migration:** All existing `Default` values are resolved to their computed effective visibility and persisted as `Public` or `Private`.

### Workspace Model

- **Remove** `IsPublicAccessEnabled` boolean
- **Keep** `Slug` — null means no gallery has been set up
- Public access is implicitly enabled when `Slug` is non-null and at least one entity is effectively public
- A slug can be **reserved** without any published content (gallery shows empty state)

### Collection, Category, Item Models

- `Visibility` field remains, now two-state (`Public` / `Private`)
- `EffectiveIsPublic` remains as a computed property:
  - An entity is effectively public when its own `Visibility == Public` AND all ancestors have `Visibility == Public` AND workspace has a slug
- `Visibility` represents **user intent**; `EffectiveIsPublic` represents **actual visibility**
- UI displays badges based on `EffectiveIsPublic`, not `Visibility`

### Default Visibility on Creation

- New item in a public category → defaults to `Public`
- New item in a private category → defaults to `Private`
- New category in a public collection → defaults to `Public`
- New category in a private collection → defaults to `Private`
- User can override during creation

---

## Backend Service Changes

### VisibilityService Rewrite

**PublishAsync(entity):**
- Sets entity `Visibility` to `Public`
- Auto-promotes all private ancestors to `Public` (item → category → collection)
- Returns a result describing what changed:
  ```json
  {
    "published": { "type": "item", "id": 42, "name": "Omega Speedmaster" },
    "promoted": [
      { "type": "category", "id": 5, "name": "Vintage Watches" },
      { "type": "collection", "id": 1, "name": "My Collection" }
    ],
    "childrenPublished": 0,
    "requiresSlugSetup": false
  }
  ```
- If workspace has no slug, returns `requiresSlugSetup: true`

**PublishCategoryAsync(categoryId, includeChildren):**
- Sets category to `Public`, auto-promotes parents
- If `includeChildren: true`, sets all items in the category to `Public`
- Same for subcategories and their items

**PublishCollectionAsync(collectionId, includeChildren):**
- Sets collection to `Public`
- If `includeChildren: true`, sets all categories and items to `Public`

**UnpublishAsync(entity):**
- Sets entity `Visibility` to `Private`
- Does NOT cascade to children — children retain their `Visibility` values
- `EffectiveIsPublic` recomputation handles the rest (children become effectively private because parent is private)
- Returns affected counts:
  ```json
  {
    "unpublished": { "type": "category", "id": 5, "name": "Vintage Watches" },
    "affectedPublicItems": 12,
    "affectedPublicCategories": 2
  }
  ```

**ComputeEffectiveVisibility** stays but simplifies:
- Entity is effectively public when: own `Visibility == Public` AND all ancestors `Visibility == Public` AND workspace has a slug

### API Endpoints

**New publish/unpublish endpoints:**

- `POST /api/workspaces/{workspaceId}/collections/{collectionId}/publish` — body: `{ includeChildren: bool }`
- `POST /api/workspaces/{workspaceId}/collections/{collectionId}/unpublish`
- `POST /api/workspaces/{workspaceId}/categories/{categoryId}/publish` — body: `{ includeChildren: bool }`
- `POST /api/workspaces/{workspaceId}/categories/{categoryId}/unpublish`
- `POST /api/workspaces/{workspaceId}/items/{itemId}/publish`
- `POST /api/workspaces/{workspaceId}/items/{itemId}/unpublish`
- `POST /api/workspaces/{workspaceId}/items/bulk-publish` — body: `{ itemIds: int[] }`
- `POST /api/workspaces/{workspaceId}/items/bulk-unpublish` — body: `{ itemIds: int[] }`

**Preview endpoints (for unpublish confirmation modals):**

- `GET /api/workspaces/{workspaceId}/categories/{categoryId}/unpublish-preview`
- `GET /api/workspaces/{workspaceId}/collections/{collectionId}/unpublish-preview`

**Removed:**

- `Visibility` field removed from existing create/update DTOs for items, categories, and collections. Visibility managed exclusively through publish/unpublish endpoints.
- `PUT /api/workspaces/{workspaceId}/public-access` endpoint removed. Slug management stays in existing workspace update endpoint.

**Migration:**

- `Default` enum value removed; existing rows resolved to effective value
- `IsPublicAccessEnabled` column dropped; workspaces that had it enabled retain their slugs

---

## Frontend UI Design

### Item Card Visibility Indicators

**Public badge:** Corner pill badge (top-right) with eye icon and "Public" text. Blue color (`#63b3ed`). Always visible on public items.

**Private items:** No badge — absence of indicator means private.

### Publish Action (One-Click)

**On item cards (desktop):**
- Hover reveals a green "Publish" button (top-right corner) with an up-arrow icon
- Visually distinct from the blue "Public" status badge: different color (green), different icon (up-arrow vs eye), different purpose (action vs status)

**On public item cards (desktop):**
- Blue "Public" badge is always visible
- On hover, badge morphs to red "Unpublish" button with crossed-out eye icon

**Three distinct visual treatments:**
- **Publish** (action): Green + up-arrow icon. "Send it up to the gallery."
- **Public** (status): Blue + eye icon. "This is being seen."
- **Unpublish** (hover action): Red + crossed-out eye icon. "Remove from gallery."

**On mobile/touch:**
- No hover-to-publish on cards (no hover available)
- Tap card to open detail view, publish from there
- Long-press card to enter bulk selection mode

### Visibility Filter

Filter bar above item grid with three options: All / Public / Private

- Segmented button style
- Shows count: "Showing X items"
- CSS-only animation: non-matching items fade out (`opacity: 0`) and scale down (`transform: scale(0.95)`) over 0.25s ease. Grid reflows naturally.

### Bulk Actions

- Desktop: checkbox selection on cards (checkbox appears on hover or when selection mode active)
- Mobile: long-press to enter selection mode, tap to select additional items
- Bulk action bar appears when items are selected: "[X] items selected | Publish Selected | Make Private | Cancel"

### Detail View

- Simple two-state toggle (Public/Private) replacing the old three-state VisibilityToggle
- Same publish/unpublish behavior as card actions

### Category & Collection Publish

**Publish prompt modal (categories and collections):**
- "Publish category 'Vintage Watches'? This category has X items."
- Option A: "Publish the category and all X items"
- Option B: "Publish the category only (add items individually later)"
- If category has subcategories, counts include those: "X subcategories and Y items"
- Same pattern for collections

**Unpublish confirmation modal (categories and collections):**
- Categories: "This category has X items currently visible in your public gallery. They will be hidden, but if you make this category public again, they'll reappear. Continue?"
- Collections: "This collection has X categories and Y items currently visible in your public gallery. They will all be hidden, but if you make this collection public again, they'll reappear. Continue?"

### First-Publish Modal

Triggered the first time a user publishes anything, when the workspace has no slug:

- Title: "Set Up Your Public Gallery"
- Body: "You're about to publish your first item. To make it visible, you need a URL for your public gallery."
- Input: slug field with live preview URL
- Validation: lowercase, alphanumeric, hyphens, no double hyphens, unique
- Buttons: "Create Gallery & Publish" / "Cancel"
- If slug already reserved in settings: modal still appears but with slug pre-populated and simpler message: "You're about to publish your first item. Your gallery URL is [url]. Continue?"
- After confirmation, the original publish action completes automatically

### Auto-Promotion Toast

After publishing an item that required parent promotion:
- "**Omega Speedmaster** published"
- Subtext: "Category 'Vintage Watches' and collection 'My Collection' are now visible in your gallery"

### Header Changes

- **Slug exists:** Persistent "Public Gallery" link (globe icon) in app header. Opens public gallery in new tab.
- **No slug:** "Set Up Public Gallery" link that opens the slug setup in workspace settings.

### Workspace Settings Changes

- **Remove** `IsPublicAccessEnabled` checkbox
- **Keep** slug field for reservation and management
- Slug field note: "Reserve your gallery URL. Your gallery becomes active when you publish your first item."

---

## Component Changes Summary

### Modified Components

- **`VisibilityToggle.tsx`** — Replace or remove. Functionality replaced by publish/unpublish buttons and detail view toggle.
- **Item cards** — Add hover publish button, public badge, hover-to-unpublish behavior.
- **Item list view** — Add visibility filter bar and bulk selection.
- **Category list/tree view** — Add publish/unpublish buttons and badges on category entries.
- **Collection view** — Add publish/unpublish on collection header.
- **`WorkspaceEditModal.tsx`** — Remove `IsPublicAccessEnabled` checkbox. Keep slug field with reservation note.
- **Item/Category creation forms** — Default visibility from parent, simple toggle to override.

### New Components

- **`PublishConfirmModal`** — Category/collection publish prompt (all children vs container only)
- **`UnpublishConfirmModal`** — Affected counts and reassurance about re-publish
- **`SlugSetupModal`** — First-publish slug creation, pre-populates if reserved
- **`PublishToast`** — Confirmation showing what was published and what was auto-promoted
- **`BulkActionBar`** — Selection bar with publish/unpublish/cancel actions
- **`VisibilityFilter`** — All/Public/Private filter bar with counts and CSS animation

---

## Edge Cases

### Concurrent Access
Last-write-wins is acceptable. Each publish/unpublish operation is atomic at the entity level.

### Empty Public Gallery
If all items are unpublished, the gallery URL stays active but shows an empty state. Reserved-but-never-activated slugs show the same empty state. No 404 for valid slugs.

### Deleting Public Entities
Deleting a public item removes it from the gallery immediately. No special handling beyond existing delete behavior. Deleting a public category: items follow existing delete/orphan behavior and retain their visibility intent.

### Slug Conflicts
Same as today: unique validation with real-time feedback.

### URL Permanence
URLs return 404 consistently whether an item was never public, never existed, or was taken private. No information leakage.

### Mobile/Touch
- No hover-to-publish on cards; publish available in detail view
- Long-press card to enter bulk selection mode
- Bulk action bar appears at bottom of screen
