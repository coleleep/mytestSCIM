# Department Attribute + Okta Import Support

**Date:** 2026-06-29  
**Status:** Approved

## Overview

Add support for the `department` attribute on SCIM users using the standard enterprise extension schema (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`), and ensure the server is fully compatible with Okta's Import Users flow.

## Goals

- Accept, persist, and return `department` via the enterprise extension namespace
- Okta Import reads users from this server and maps `department` correctly
- Display `department` in the web UI users table

## Non-Goals

- No `externalId` support (existing `userName` matching is sufficient)
- No other enterprise extension attributes beyond `department`
- No DB schema changes

---

## Data Layer

No database migration required. `scim_data` is JSONB and stores arbitrary structure.

The enterprise extension is stored as a top-level key in `scim_data`:

```json
{
  "schemas": [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
  ],
  "userName": "alice@example.com",
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
    "department": "Engineering"
  }
}
```

The enterprise schema URI is added to `schemas` only when the enterprise extension block is present.

---

## SCIM Endpoint Changes (`routes/users.js`)

### POST `/scim/v2/Users`
- Read `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User` from the request body
- If present, include it in `newUser` and add the enterprise schema URI to the `schemas` array

### PUT `/scim/v2/Users/:id`
- Same as POST — read and replace the enterprise block wholesale (PUT is a full replace)
- If absent from the request, omit the enterprise block and schema URI from the updated user

### PATCH `/scim/v2/Users/:id`
- Handle `replace` operations targeting the enterprise extension, including:
  - `{ op: "replace", path: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", value: "Sales" }`
  - `{ op: "replace", value: { "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { "department": "Sales" } } }`
- Update the enterprise block in the stored `scim_data` and ensure the schema URI is in `schemas`

### GET `/scim/v2/Users` and GET `/scim/v2/Users/:id`
- No changes — already returns `scim_data` verbatim, which will now include the enterprise extension

---

## Schema Advertisement (`server.js`)

### Add `ENTERPRISE_USER_SCHEMA` constant

```json
{
  "id": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
  "name": "EnterpriseUser",
  "description": "Enterprise User",
  "attributes": [
    {
      "name": "department",
      "type": "string",
      "multiValued": false,
      "description": "Identifies the name of a department.",
      "required": false,
      "mutability": "readWrite",
      "returned": "default"
    }
  ],
  "meta": {
    "resourceType": "Schema",
    "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
  }
}
```

### Update `SCHEMAS` array
Add `ENTERPRISE_USER_SCHEMA` to the `SCHEMAS` array so `/scim/v2/Schemas` returns it. Okta reads this endpoint during import to discover mappable attributes.

No changes to `SERVICE_PROVIDER_CONFIG` or resource types.

---

## UI Changes (`views/users.ejs`)

- Add a `Department` column to the users table
- Value: `user["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]?.department ?? 'N/A'`
- Column uses `white-space: nowrap` and reasonable `max-width` to stay compact; the existing `overflow-x: auto` wrapper handles overflow
- Positioned after `Full Name`, before `Email`

---

## Okta Import Compatibility Checklist

- `/scim/v2/Schemas` returns the enterprise schema with `department` declared — Okta uses this to surface the attribute in attribute mapping UI
- `GET /Users` returns `schemas` array including the enterprise URI on users that have `department`
- `userName` is present on all users — used for matching during import
- No other changes required; existing pagination and filtering on `GET /Users` is sufficient for Okta's import scan
