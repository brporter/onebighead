# Tenant & User Soft-Delete Design

**Date:** 2026-02-03
**Status:** Approved

## Overview

When a single-tenant admin deletes their only tenant, the system should soft-delete both the tenant and the user account. Upon signing back in, the user can restore their tenant(s) or create a new one.

## Requirements

### Trigger Condition
User soft-delete occurs when ALL of these are true:
- User is admin of exactly one tenant
- User has no other tenant memberships
- User deletes that tenant

### Behaviors

| Event | Behavior |
|-------|----------|
| Tenant deletion (trigger met) | Soft-delete tenant AND user, log out, redirect to homepage |
| Tenant deletion (trigger not met) | Existing behavior - soft-delete tenant, switch to next tenant |
| Soft-deleted user signs in | User account restored immediately (no time limit) |
| Sign-in with restorable tenants | Show restoration modal |
| Sign-in with no restorable tenants | Redirect to tenant creation flow |
| Tenant 30-day countdown | Display only (no auto-deletion yet) |

---

## Data Model Changes

### User Model Additions

```csharp
public bool IsDeleted { get; set; } = false;
public DateTime? DeletedAt { get; set; }
```

No `DeletedByUserId` needed since users can only soft-delete themselves via this flow.

### Tenant Model

No changes - already has soft-delete fields (`IsDeleted`, `DeletedAt`, `DeletedByUserId`).

---

## API Changes

### Modified Endpoints

#### DELETE /api/tenants/{tenantId}

**Additional response field:**
```json
{
  "success": true,
  "newActiveTenantId": null,
  "userSoftDeleted": true  // NEW: indicates user should be logged out
}
```

**Additional backend logic in TenantDeletionService:**
1. After soft-deleting tenant, check if user meets trigger condition
2. If yes, soft-delete user account
3. Return `userSoftDeleted: true` flag

#### POST /api/auth/callback (OAuth callback)

**Additional logic:**
1. After finding existing user, check `user.IsDeleted`
2. If soft-deleted, restore immediately: `IsDeleted = false`, `DeletedAt = null`
3. Continue with normal auth flow

### New Endpoints

#### GET /api/users/me/restorable-tenants

**Security:** User ID extracted from JWT `sub` claim only. No parameters accepted.

**Response:**
```json
[
  {
    "tenantId": 123,
    "name": "My Collection",
    "deletedAt": "2026-01-15T10:30:00Z",
    "daysRemaining": 23,
    "stats": {
      "collectionCount": 3,
      "itemCount": 47,
      "categoryCount": 12,
      "imageCount": 89
    }
  }
]
```

**Eligibility criteria:**
- Tenant is soft-deleted (`IsDeleted = true`)
- User had `TenantRole = TenantAdmin` for that tenant

#### POST /api/tenants/restore

**Security:** User ID extracted from JWT `sub` claim only.

**Request:**
```json
{
  "tenantIds": [123, 456]
}
```

**Validation:**
- User must have been TenantAdmin of each requested tenant
- Returns 403 Forbidden if user wasn't admin of any requested tenant

**Actions:**
- Clear `IsDeleted`, `DeletedAt`, `DeletedByUserId` on each tenant
- Set first tenant as user's `ActiveTenantId`

**Response:**
```json
{
  "restoredTenants": [123, 456],
  "activeTenantId": 123
}
```

#### POST /api/tenants/{tenantId}/restore

Single-tenant variant for Settings page restoration.

**Security:** User ID from JWT, validates TenantAdmin role.

**Response:**
```json
{
  "tenantId": 123,
  "name": "My Collection"
}
```

---

## Frontend Changes

### Restoration Modal Component

**Location:** `frontend/src/components/tenant/TenantRestorationModal.tsx`

**Trigger:** Shown after sign-in when user has no active tenant but has restorable tenants.

**UI:**
```
┌─────────────────────────────────────────────┐
│  Welcome Back                               │
│                                             │
│  Your account has been restored. Choose     │
│  how you'd like to continue:                │
│                                             │
│  ○ Restore existing tenant(s)               │
│    ┌─────────────────────────────────────┐  │
│    │ ☑ My Collection                     │  │
│    │   3 collections, 47 items           │  │
│    │   23 days until permanent deletion  │  │
│    ├─────────────────────────────────────┤  │
│    │ ☐ Work Projects                     │  │
│    │   1 collection, 12 items            │  │
│    │   18 days until permanent deletion  │  │
│    └─────────────────────────────────────┘  │
│                                             │
│  ○ Create a new tenant                      │
│                                             │
│           [Continue]                        │
└─────────────────────────────────────────────┘
```

**Behavior:**
- Radio selection: restore OR create (mutually exclusive)
- If restore selected: checkboxes for tenant selection (at least one required)
- Continue button calls appropriate API then navigates to dashboard or tenant creation

### TenantDeletionSection Changes

**File:** `frontend/src/components/tenant/TenantDeletionSection.tsx`

After successful deletion:
1. Check response for `userSoftDeleted: true`
2. If true: call logout, redirect to homepage (`/`)
3. If false: existing behavior (switch to new active tenant)

### RequireAuth / User Context Changes

**File:** `frontend/src/components/common/RequireAuth.tsx`

After authentication:
1. Check if user has zero active tenants
2. If zero tenants: call `GET /api/users/me/restorable-tenants`
3. If restorable tenants exist: show restoration modal
4. If no restorable tenants: redirect to tenant creation flow
5. Never show collection wizard when there's no tenant context

### Settings - My Tenants Enhancement

**File:** `frontend/src/views/SettingsView.tsx` (or tenant list component)

Add "Deleted Tenants" section below active tenants:

```
Deleted Tenants
┌─────────────────────────────────────┐
│ Old Project                         │
│ 15 days until permanent deletion    │
│                          [Restore]  │
└─────────────────────────────────────┘
```

- Shows only tenants where user was TenantAdmin
- Restore button calls `POST /api/tenants/{tenantId}/restore`
- On success: tenant moves to Active list, toast confirmation

---

## Bug Fixes

### Bug 1: Deleting last tenant returns to Settings

**Current:** User stays on Settings in broken state.
**Fix:** Check `userSoftDeleted` flag, logout and redirect to homepage.

### Bug 2: Sign-in without tenant shows Collection wizard

**Current:** `RequireAuth` checks `hasCompletedWelcome` which fails without tenant context.
**Fix:** Check for zero active tenants first, redirect to restoration modal or tenant creation.

---

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| User is admin of 2+ tenants, deletes one | Normal soft-delete, no user soft-delete, switch to other tenant |
| User is member (not admin) of another tenant | No user soft-delete (has other membership) |
| User was non-admin member of deleted tenant | Tenant does NOT appear in their restorable list |
| User tries to restore tenant they weren't admin of | 403 Forbidden |
| User restores tenant, then deletes it again | Same flow repeats, 30-day timer resets |
| All restorable tenants expire before user returns | Modal shows "Create new tenant" as only option |

---

## Security Considerations

**Critical:** All API endpoints determine user identity exclusively from JWT token claims.

- `GET /api/users/me/restorable-tenants` - No userId parameter; extract from `sub` claim
- `POST /api/tenants/restore` - Validate user was TenantAdmin via token identity
- `POST /api/tenants/{tenantId}/restore` - Same validation

Never accept user identity from request parameters for these operations.

---

## Out of Scope (Future Work)

- Background job for permanent deletion after 30 days
- Admin ability to restore tenants on behalf of users
- Email notifications about upcoming permanent deletion
