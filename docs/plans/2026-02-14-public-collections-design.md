# Public Collection Browsing Design

## Summary

Enable anonymous users to browse collections, categories, and items marked as public via workspace-scoped URLs. Workspace admins must explicitly opt in and set a URL slug before public access is available.

## Data Model Changes

### Workspace

Add two fields to the Workspace model:

- `Slug` (string, unique, nullable): URL-friendly identifier (lowercase alphanumeric + hyphens, 3-50 chars)
- `IsPublicAccessEnabled` (bool, default false): Explicit opt-in for public access

Both must be set before public URLs work. A migration adds these columns and a unique index on `Slug`.

## Backend API

### PublicController

New controller inheriting `ControllerBase` (not `ApiControllerBase`). All endpoints are `[AllowAnonymous]` and read-only.

| Endpoint | Description |
|----------|-------------|
| `GET /api/public/{slug}` | Workspace public profile (name, slug) |
| `GET /api/public/{slug}/collections` | List all public collections |
| `GET /api/public/{slug}/collections/{id}` | Collection detail + public category tree |
| `GET /api/public/{slug}/collections/{id}/items` | Public items (optional `categoryId` query param) |
| `GET /api/public/{slug}/items/{id}` | Item detail: properties, images |

### Key Behaviors

- Resolves workspace by slug; returns 404 if not found or public access disabled
- Filters results through `VisibilityService` -- only returns entities where `effectiveIsPublic == true`
- Uses dedicated public DTOs (`PublicCollectionDto`, `PublicItemDto`, etc.) that omit internal fields
- No mutation endpoints

### Public DTOs

Separate DTO types in `DTOs/PublicDtos.cs`:

- `PublicWorkspaceDto`: name, slug
- `PublicCollectionDto`: id, name, description, imageUrl, itemCount
- `PublicCategoryDto`: id, name, parentId, children
- `PublicItemDto`: id, name, description, properties, images, categoryName, collectionName
- `PublicItemSummaryDto`: id, name, primaryImageUrl (for list views)

### Image Access

Public item images must be accessible without authentication. The existing image endpoint needs an `[AllowAnonymous]` override for images belonging to public items.

## Frontend

### Routing

New public routes added outside the `RequireAuth` wrapper:

```
/public/:slug                           -> PublicWorkspacePage (collection list)
/public/:slug/collections/:collectionId -> PublicCollectionPage (category sidebar + items)
/public/:slug/items/:itemId             -> PublicItemPage (item detail)
```

### Components

New components in `components/public/`:

- `PublicLayout`: Shell with clean header (workspace name, "Sign in" link), footer
- `PublicCollectionList`: Grid/list of public collections
- `PublicCollectionView`: Category tree sidebar + item grid
- `PublicItemView`: Item detail with properties + image gallery (reuses existing `ImageGallery`)

### API Module

New `api/publicApi.ts` calling the public endpoints. No auth cookies required.

## Workspace Settings

New "Public Access" section in workspace settings:

- Toggle for `IsPublicAccessEnabled`
- Slug input with validation and uniqueness check
- Public URL preview
- Slug must be set before toggle can be enabled

## Security

- Public DTOs are separate types preventing accidental exposure of internal fields
- Public slugs are discoverable by design (user opted in)
- Rate limiting not in initial scope but controller is a natural extension point
- Public endpoints never expose user lists, workspace settings, templates, or other internal data
