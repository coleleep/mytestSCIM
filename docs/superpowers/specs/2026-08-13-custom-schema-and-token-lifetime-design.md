# Design: customExt schema extension + 90-day OAuth token lifetime

## Context

Recent commits (`16702f8` → `7b1e6a4` → `4a1f4ad` → `a7f582d` → `0dab8bf`) added and then partially reverted an enterprise schema extension (`department`) after Okta's SCIM importer threw a `ClassCastException`. The exact trigger is unconfirmed:

1. `16702f8` listed the enterprise schema in `/scim/v2/Schemas` only — no fix followed, implying this state may have worked.
2. `4a1f4ad` additionally wired it into `UserResourceType.schemaExtensions`.
3. `a7f582d` removed `schemaExtensions` "to fix ClassCastException".
4. `0dab8bf` removed the schema from `/Schemas` too "to fix ClassCastException" — but it's unconfirmed whether the exception was re-tested and still occurred after step 3, or whether this was precautionary.

This spec adds a second, independent schema extension (`customExt`) in the one state never confirmed as broken — listed in `/Schemas`, not wired into `schemaExtensions` — so the next Okta import test produces new evidence about the actual trigger.

This spec also covers an unrelated, independent change: extending the OAuth token's advertised lifetime to 90 days.

## 1. OAuth token lifetime (90 days)

Change `expires_in` from `3600` to `7776000` (90 × 24 × 3600) in both grant-type responses in `server.js`:
- `client_credentials` grant (`server.js:160`)
- `authorization_code` grant (`server.js:170`)

`SCIM_ACCESS_TOKEN` is a static token (from `SCIM_ACCESS_TOKEN` env var or randomly generated at startup) with no server-side expiry enforcement — this change only affects the advertised `expires_in` value returned to the client. No expiration tracking logic exists today and none is being added.

## 2. customExt schema extension

### Schema definition (`server.js`)

Add a new constant alongside `ENTERPRISE_USER_SCHEMA`:

```js
const CUSTOM_EXTENSION_SCHEMA = {
    "id": "urn:ietf:params:scim:schemas:extension:custom:2.0:User",
    "name": "CustomUser",
    "description": "Custom User Extension",
    "attributes": [
        {
            "name": "customExt",
            "type": "string",
            "multiValued": false,
            "description": "Custom extension attribute.",
            "required": false,
            "mutability": "readWrite",
            "returned": "default"
        }
    ],
    "meta": {
        "resourceType": "Schema",
        "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:extension:custom:2.0:User"
    }
};
```

Add it to the `SCHEMAS` array so it's discoverable at `/scim/v2/Schemas`:

```js
const SCHEMAS = [USER_SCHEMA, GROUP_SCHEMA, CUSTOM_EXTENSION_SCHEMA];
```

Do **not** add it to `USER_RESOURCE_TYPE.schemaExtensions`. This is deliberate — see Context above.

### User data handling (`routes/users.js`)

Mirror the existing enterprise-extension (`department`) pattern:

- Define `const CUSTOM_SCHEMA = 'urn:ietf:params:scim:schemas:extension:custom:2.0:User';`
- POST and PUT already pass through arbitrary extension objects generically (`scimUser[ENTERPRISE_SCHEMA]` pattern) — extend the same generic handling to `scimUser[CUSTOM_SCHEMA]`, including adding/removing it from the `schemas` array based on presence.
- PATCH currently has explicit, hardcoded path handling for `department` (dotted-path format `urn:...:department` and value-object format). Add equivalent explicit handling for `customExt` in both formats.

## Testing / verification

- Automated: none of the existing code has unit tests; verify manually via SCIM requests (POST/PUT/PATCH a user with the custom extension attribute, confirm round-trip) and `GET /scim/v2/Schemas` to confirm the new schema appears.
- Okta-specific: after deploying, re-run the Okta app import/provisioning flow and observe whether the `ClassCastException` recurs. Record the result — it resolves the open question about whether `/Schemas` listing alone (independent of `schemaExtensions`) is sufficient to trigger Okta's importer bug.

## Out of scope

- Real token expiration enforcement (only the advertised `expires_in` value changes).
- Re-adding `schemaExtensions` wiring for either the enterprise or custom extension — deferred until the Okta re-test above produces a result.
- Any UI changes to surface `customExt` in the Users view (not requested).
