# Centralized Publish Manager Design

## Goal

Replace the scattered per-entity publish/unpublish endpoints and frontend flows with a centralized two-endpoint API (`preflight` + `execute`) and a single unified `PublishResolver` UI component. Any component in the app can trigger a publish or unpublish operation by expressing intent; the centralized system handles dependency analysis, user resolution, and atomic execution.

## Design Decisions

- **Both publish and unpublish** are centralized through the same endpoints.
- **All three entity types** (items, categories, collections) use the same flow.
- **Bulk operations** use a single server-side preflight that deduplicates dependencies across all entities.
- **Preflight surfaces only blockers**, not optional children. Publishing children is a separate action.
- **Typed dependency kinds** (discriminated union) — the frontend maps each kind to specific UI treatment.
- **Atomic execution** — the entire bulk-update succeeds or fails in a single transaction.
- **Clean break** — old per-entity publish endpoints and the `IVisibilityService` interface are removed entirely.

---

## API Contract

### Preflight Endpoint

`POST /api/workspaces/{workspaceId}/publish/preflight`

Analyzes the requested publish/unpublish action and returns a list of requirements that must be resolved before execution.

**Request:**

```json
{
  "action": "publish",
  "entities": [
    { "type": "item", "id": 42 },
    { "type": "category", "id": 7 }
  ]
}
```

- `action`: `"publish"` or `"unpublish"`
- `entities`: one or more entity references. Each has `type` (`"item"`, `"category"`, `"collection"`) and `id`.

**Response (ready to execute):**

```json
{
  "ready": true,
  "requirements": []
}
```

**Response (requirements exist — publish):**

```json
{
  "ready": false,
  "requirements": [
    {
      "kind": "workspace-slug-required",
      "workspaceId": 1,
      "workspaceName": "My Workspace"
    },
    {
      "kind": "collection-not-public",
      "collectionId": 5,
      "collectionName": "Vintage Cars"
    },
    {
      "kind": "category-not-public",
      "categoryId": 7,
      "categoryName": "Sedans"
    }
  ]
}
```

**Response (requirements exist — unpublish):**

```json
{
  "ready": false,
  "requirements": [
    {
      "kind": "unpublish-will-hide-children",
      "entityType": "collection",
      "entityId": 5,
      "entityName": "Vintage Cars",
      "affectedPublicItems": 23,
      "affectedPublicCategories": 4
    }
  ]
}
```

**Requirement kinds:**

| Kind | When | User Action |
|------|------|-------------|
| `workspace-slug-required` | Workspace has no slug and this would be the first public entity | Text input: enter slug |
| `collection-not-public` | A parent collection is private | Acknowledgment: agree to make it public |
| `category-not-public` | A parent category is private | Acknowledgment: agree to make it public |
| `unpublish-will-hide-children` | Unpublishing will make public descendants effectively hidden | Acknowledgment: understand the impact |

### Execute Endpoint

`POST /api/workspaces/{workspaceId}/publish/execute`

Applies the publish/unpublish action atomically, including all resolved dependencies.

**Request:**

```json
{
  "action": "publish",
  "entities": [
    { "type": "item", "id": 42 }
  ],
  "resolutions": [
    {
      "kind": "workspace-slug-required",
      "slug": "my-gallery"
    },
    {
      "kind": "collection-not-public",
      "collectionId": 5
    },
    {
      "kind": "category-not-public",
      "categoryId": 7
    }
  ]
}
```

- `resolutions`: one entry per requirement from preflight. The frontend confirms all dependencies are resolved.

For unpublish:

```json
{
  "action": "unpublish",
  "entities": [
    { "type": "collection", "id": 5 }
  ],
  "resolutions": [
    {
      "kind": "unpublish-will-hide-children",
      "entityType": "collection",
      "entityId": 5
    }
  ]
}
```

**Response (success):**

```json
{
  "success": true,
  "changed": [
    { "type": "item", "id": 42, "name": "1967 Mustang" }
  ],
  "promoted": [
    { "type": "collection", "id": 5, "name": "Vintage Cars" },
    { "type": "category", "id": 7, "name": "Sedans" }
  ],
  "workspaceSlugSet": "my-gallery"
}
```

**Response (failure):**

```json
{
  "success": false,
  "error": "Slug 'my-gallery' is already taken",
  "requirements": [
    {
      "kind": "workspace-slug-required",
      "workspaceId": 1,
      "workspaceName": "My Workspace"
    }
  ]
}
```

On failure, a fresh `requirements` list is returned so the frontend can re-render the resolver UI without another preflight call.

---

## Backend Architecture

### New Controller: `PublishManagerController`

Inherits from `ApiControllerBase` (workspace-scoped). Two action methods mapping to the two endpoints above. Delegates all logic to `IPublishManagerService`.

### New Service: `IPublishManagerService` / `PublishManagerService`

Absorbs all functionality from the deleted `IVisibilityService`:

- **Preflight logic:** Loads referenced entities and their ancestor chains. For publish: walks up the hierarchy collecting private ancestors as requirements, checks workspace slug. For unpublish: walks down counting public descendants as impact warnings. Deduplicates across all entities in the request.
- **Execute logic:** Re-runs preflight internally to get current requirements. Validates every requirement has a matching resolution. Validates slug uniqueness if applicable. Applies all visibility changes in a single transaction (promoted ancestors first, then target entities). Returns result with changed/promoted entity info.
- **Effective visibility computation:** The `ComputeEffectiveVisibility` overloads (for Category, Item, Collection, and their collection variants) move here from the deleted `VisibilityService`.

### New DTOs: `PublishManagerRequests.cs`

All request and response types for both endpoints, including:

- `PreflightRequest`, `PreflightResponse`
- `ExecuteRequest`, `ExecuteResponse`
- `EntityRef` (type + id)
- Requirement types (discriminated by `kind`)
- Resolution types (discriminated by `kind`)
- `PublishedEntityInfo` (type + id + name)

---

## Frontend Architecture

### New API Module: `api/publishManager.ts`

Two functions:

- `preflight(workspaceId, action, entities)` → `PreflightResponse`
- `execute(workspaceId, request)` → `ExecuteResponse`

### New Context: `PublishContext`

Exposes two methods to the entire app:

- `requestPublish(entities: EntityRef[]): void`
- `requestUnpublish(entities: EntityRef[]): void`

Manages the `PublishResolver` lifecycle: stores pending intent, triggers preflight, handles completion callbacks including cache invalidation and user context refresh.

### New Component: `PublishResolver`

A single modal component rendered once at the app level. Handles the complete publish/unpublish flow:

1. Receives trigger from `PublishContext`
2. Calls preflight
3. If `ready: true` — calls execute immediately, shows success toast
4. If requirements exist — renders resolution UI:
   - `workspace-slug-required` → slug input with validation and URL preview
   - `collection-not-public` → acknowledgment checkbox with collection name
   - `category-not-public` → acknowledgment checkbox with category name
   - `unpublish-will-hide-children` → impact summary with item/category counts
5. Submit disabled until all requirements resolved
6. On submit, calls execute with resolutions
7. On execute failure, re-renders with fresh requirements from the error response
8. On success: invalidates caches, refetches user context (if slug changed), shows toast, closes

### Shared UI Components

- **`PublishButton`** — existing shared component. onClick calls `requestPublish` from context. Used by `ItemCard`, `CollectionList`, `CategoryView`, `CategoryManagerForm`.
- **`PublicBadge`** — existing shared component. onClick calls `requestUnpublish` from context. Used by the same components.

No component contains any publish logic beyond calling `requestPublish` or `requestUnpublish` with entity references. No component renders its own slug input, confirmation dialog, or impact preview. All publish UI flows through `PublishResolver`.

### Integration Pattern

`App.tsx` wraps the application with `PublishContext.Provider` and renders `PublishResolver` once. Any component anywhere in the tree can trigger a publish flow via the context.

---

## Data Flow

Complete flow for publishing an item whose category and collection are private, workspace has no slug:

1. `ItemCard` onClick → `publishContext.requestPublish([{ type: 'item', id: 42 }])`
2. `PublishResolver` calls `publishManager.preflight(wsId, 'publish', entities)`
3. Backend loads item 42, category 7, collection 5, workspace 1. Returns three requirements: `workspace-slug-required`, `collection-not-public`, `category-not-public`.
4. `PublishResolver` renders resolution UI. User enters slug, checks both acknowledgment boxes.
5. User clicks "Publish". `PublishResolver` calls `publishManager.execute(wsId, { action, entities, resolutions })`.
6. Backend re-validates requirements, checks slug uniqueness. In single transaction: sets workspace slug, sets collection/category/item visibility to Public.
7. Returns success with changed and promoted entity info.
8. `PublishResolver` invalidates caches, refetches user context, shows toast, closes.
9. Calling component re-renders with fresh data showing updated visibility state.

For unpublish, the same flow — requirements are impact warnings, execution sets visibility to Private.

For bulk (e.g., 10 items in `ItemList`), the same flow — preflight deduplicates across all items, user resolves one set of requirements, one atomic execute.

---

## Migration and Cleanup

### Backend — Deleted

| File | Reason |
|------|--------|
| `Controllers/PublishController.cs` | Replaced by `PublishManagerController` |
| `DTOs/PublishRequests.cs` | Replaced by `PublishManagerRequests.cs` |
| `Services/VisibilityService.cs` | Absorbed into `PublishManagerService` |
| `Services/IVisibilityService.cs` | Absorbed into `IPublishManagerService` |
| `Services/PublishResult.cs` | Replaced by new response types in `PublishManagerRequests.cs` |

### Backend — Added

| File | Purpose |
|------|---------|
| `Controllers/PublishManagerController.cs` | Two endpoints: preflight + execute |
| `Services/IPublishManagerService.cs` | Interface: preflight, execute, effective visibility computation |
| `Services/PublishManagerService.cs` | All publish logic and visibility computation |
| `DTOs/PublishManagerRequests.cs` | All request/response types for both endpoints |

### Backend — Modified

| File | Change |
|------|--------|
| `Program.cs` (or DI setup) | Replace `IVisibilityService` with `IPublishManagerService` |
| Any service/controller that injected `IVisibilityService` | Inject `IPublishManagerService` instead |

### Frontend — Deleted

| File | Reason |
|------|--------|
| `api/publish.ts` | Replaced by `api/publishManager.ts` |
| `components/common/PublishConfirmModal.tsx` | Absorbed into `PublishResolver` |
| `components/common/UnpublishConfirmModal.tsx` | Absorbed into `PublishResolver` |
| `components/common/SlugSetupModal.tsx` | Absorbed into `PublishResolver` |
| Tests for the above three modals | Replaced by `PublishResolver` tests |

### Frontend — Added

| File | Purpose |
|------|---------|
| `api/publishManager.ts` | Preflight + execute API calls |
| `components/common/PublishResolver.tsx` | Unified publish/unpublish flow UI |
| `contexts/PublishContext.tsx` | `requestPublish` / `requestUnpublish` context |
| Tests for the above | Full coverage |

### Frontend — Modified

| File | Change |
|------|--------|
| `contexts/DataContext.tsx` | Remove all publish/unpublish methods |
| `components/item/ItemCard.tsx` | Remove publish handlers, use `requestPublish`/`requestUnpublish` |
| `components/item/ItemList.tsx` | Remove bulk publish handlers, use context methods with array |
| `components/category/CategoryManagerModal.tsx` | Remove publish/unpublish/slug handlers, use context methods |
| `components/category/CategoryManagerForm.tsx` | Remove publish/unpublish buttons, use context methods |
| `components/collection/CollectionList.tsx` | Same pattern |
| `views/CategoryView.tsx` | Same pattern |
| `App.tsx` | Wrap with `PublishContext.Provider`, render `PublishResolver` |
| `utils/types.ts` | Replace old publish types with new preflight/execute types |

---

## Testing Strategy

### Backend

**`PublishManagerServiceTests`:**

- Preflight returns correct requirements for each entity type
- Preflight deduplicates requirements across multiple entities
- Preflight for unpublish returns impact counts
- Execute validates resolutions match current requirements
- Execute rejects stale resolutions (state changed between preflight and execute)
- Execute applies all changes atomically (transaction rollback on failure)
- Execute validates slug uniqueness
- Execute rejects if any resolution is missing
- Effective visibility computation (migrated from VisibilityService tests)

**`PublishManagerControllerTests`:**

- Authorization required
- Workspace scoping enforced
- Request validation (invalid entity types, missing fields)
- End-to-end preflight → execute flow

### Frontend

**`PublishResolver.test.tsx`:**

- Renders nothing when inactive
- Calls preflight on trigger
- Auto-executes when `ready: true` (no requirements)
- Renders slug input for `workspace-slug-required`
- Renders acknowledgment for `collection-not-public` and `category-not-public`
- Renders impact warning for `unpublish-will-hide-children`
- Submit disabled until all requirements resolved
- Calls execute with correct resolutions
- Handles execute failure (re-renders with fresh requirements)
- Shows toast on success
- Invalidates caches on success
- Works for single item, single category, single collection, and bulk items

**`publishManager.test.ts`:** API module request/response mapping.

**Existing component tests updated:** `ItemCard`, `CollectionList`, `CategoryManagerModal`, etc. verify they call `requestPublish`/`requestUnpublish` with correct entity refs and no longer contain publish logic.
