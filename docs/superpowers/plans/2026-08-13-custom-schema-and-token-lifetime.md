# customExt Schema Extension + 90-Day Token Lifetime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `customExt` SCIM schema extension (discoverable at `/Schemas`, not wired into `schemaExtensions`) with full CRUD support in `routes/users.js`, and extend the OAuth token's advertised lifetime to 90 days.

**Architecture:** Mirror the existing `enterprise`/`department` extension pattern already in `server.js` and `routes/users.js` — same generic pass-through on POST/PUT, same explicit dual-format handling on PATCH. The two features (schema extension, token lifetime) are independent and touch disjoint code, so they're separate task groups with no shared state.

**Tech Stack:** Node.js (ES modules), Express, plain JS objects for SCIM payloads — no test framework in this repo. Verification is `node --check` (syntax) plus manual curl walkthroughs, per the existing project convention (no automated tests exist for any current route).

---

## Spec reference

`docs/superpowers/specs/2026-08-13-custom-schema-and-token-lifetime-design.md`

---

### Task 1: Define and advertise the customExt schema

**Files:**
- Modify: `server.js:44-64`

- [ ] **Step 1: Add the CUSTOM_EXTENSION_SCHEMA constant**

Insert immediately after the closing `};` of `ENTERPRISE_USER_SCHEMA` (currently `server.js:63`, before the `const SCHEMAS = ...` line):

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

- [ ] **Step 2: Add it to the SCHEMAS array**

Change (`server.js:64`):

```js
const SCHEMAS = [USER_SCHEMA, GROUP_SCHEMA];
```

to:

```js
const SCHEMAS = [USER_SCHEMA, GROUP_SCHEMA, CUSTOM_EXTENSION_SCHEMA];
```

Do **not** add anything to `USER_RESOURCE_TYPE` (`server.js:72`) — no `schemaExtensions` entry. This is intentional per the design spec.

- [ ] **Step 3: Verify syntax**

Run: `node --check server.js`
Expected: no output, exit code 0.

- [ ] **Step 4: Commit**

```bash
git add server.js
git commit -m "feat: advertise customExt schema extension in /scim/v2/Schemas"
```

---

### Task 2: Handle customExt on POST and PUT

**Files:**
- Modify: `routes/users.js:14`, `routes/users.js:73-91`, `routes/users.js:113-130`

- [ ] **Step 1: Add the CUSTOM_SCHEMA constant**

Change (`routes/users.js:14`):

```js
const ENTERPRISE_SCHEMA = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
```

to:

```js
const ENTERPRISE_SCHEMA = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
const CUSTOM_SCHEMA = 'urn:ietf:params:scim:schemas:extension:custom:2.0:User';
```

- [ ] **Step 2: Pass through customExt on POST**

In the POST handler, change (`routes/users.js:73-75`):

```js
    const enterpriseExt = scimUser[ENTERPRISE_SCHEMA];
    const schemas = ["urn:ietf:params:scim:schemas:core:2.0:User"];
    if (enterpriseExt) schemas.push(ENTERPRISE_SCHEMA);
```

to:

```js
    const enterpriseExt = scimUser[ENTERPRISE_SCHEMA];
    const customExt = scimUser[CUSTOM_SCHEMA];
    const schemas = ["urn:ietf:params:scim:schemas:core:2.0:User"];
    if (enterpriseExt) schemas.push(ENTERPRISE_SCHEMA);
    if (customExt) schemas.push(CUSTOM_SCHEMA);
```

Then change (`routes/users.js:91`):

```js
    if (enterpriseExt) newUser[ENTERPRISE_SCHEMA] = enterpriseExt;
```

to:

```js
    if (enterpriseExt) newUser[ENTERPRISE_SCHEMA] = enterpriseExt;
    if (customExt) newUser[CUSTOM_SCHEMA] = customExt;
```

- [ ] **Step 3: Pass through customExt on PUT**

In the PUT handler, change (`routes/users.js:113-119`):

```js
    const enterpriseExt = scimUser[ENTERPRISE_SCHEMA];
    const schemas = [...(scimUser.schemas || ["urn:ietf:params:scim:schemas:core:2.0:User"])];
    if (enterpriseExt && !schemas.includes(ENTERPRISE_SCHEMA)) schemas.push(ENTERPRISE_SCHEMA);
    if (!enterpriseExt) {
        const idx = schemas.indexOf(ENTERPRISE_SCHEMA);
        if (idx > -1) schemas.splice(idx, 1);
    }
```

to:

```js
    const enterpriseExt = scimUser[ENTERPRISE_SCHEMA];
    const customExt = scimUser[CUSTOM_SCHEMA];
    const schemas = [...(scimUser.schemas || ["urn:ietf:params:scim:schemas:core:2.0:User"])];
    if (enterpriseExt && !schemas.includes(ENTERPRISE_SCHEMA)) schemas.push(ENTERPRISE_SCHEMA);
    if (!enterpriseExt) {
        const idx = schemas.indexOf(ENTERPRISE_SCHEMA);
        if (idx > -1) schemas.splice(idx, 1);
    }
    if (customExt && !schemas.includes(CUSTOM_SCHEMA)) schemas.push(CUSTOM_SCHEMA);
    if (!customExt) {
        const idx = schemas.indexOf(CUSTOM_SCHEMA);
        if (idx > -1) schemas.splice(idx, 1);
    }
```

Then change (`routes/users.js:130`):

```js
    if (enterpriseExt) updatedUser[ENTERPRISE_SCHEMA] = enterpriseExt;
```

to:

```js
    if (enterpriseExt) updatedUser[ENTERPRISE_SCHEMA] = enterpriseExt;
    if (customExt) updatedUser[CUSTOM_SCHEMA] = customExt;
```

- [ ] **Step 4: Verify syntax**

Run: `node --check routes/users.js`
Expected: no output, exit code 0.

- [ ] **Step 5: Manual verification (requires a running server + DB)**

If you have a local instance running (`npm start` with `DATABASE_URL`, `SCIM_ACCESS_TOKEN`, etc. set), verify with:

```bash
curl -s -X POST http://localhost:3000/scim/v2/Users \
  -H "Authorization: Bearer $SCIM_ACCESS_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "userName": "custom.ext.test",
    "urn:ietf:params:scim:schemas:extension:custom:2.0:User": { "customExt": "hello" }
  }' | jq .
```

Expected: `201`, response includes `"schemas"` containing `urn:ietf:params:scim:schemas:extension:custom:2.0:User` and the extension object with `customExt: "hello"`.

- [ ] **Step 6: Commit**

```bash
git add routes/users.js
git commit -m "feat: pass through customExt extension on POST and PUT /scim/v2/Users"
```

---

### Task 3: Handle customExt on PATCH

**Files:**
- Modify: `routes/users.js:141-200`

- [ ] **Step 1: Add dotted-path and value-object handling for customExt**

In the PATCH handler, after the existing department blocks and before the closing of the `for` loop (insert after `routes/users.js:191`, i.e. right after the second department block's closing `}` and before the loop's final `}`):

```js

            // customExt path format: "urn:...:customExt"
            const customExtPath = `${CUSTOM_SCHEMA}:customExt`;
            if (op.path === customExtPath) {
                if (!user[CUSTOM_SCHEMA]) user[CUSTOM_SCHEMA] = {};
                user[CUSTOM_SCHEMA].customExt = op.value;
                if (!user.schemas.includes(CUSTOM_SCHEMA)) user.schemas.push(CUSTOM_SCHEMA);
                user.meta.lastModified = new Date().toISOString();
                changed = true;
                continue;
            }

            // customExt value object format: { op: "replace", value: { "urn:...": { "customExt": "foo" } } }
            if (!op.path && typeof op.value === 'object' && op.value[CUSTOM_SCHEMA]) {
                if (!user[CUSTOM_SCHEMA]) user[CUSTOM_SCHEMA] = {};
                Object.assign(user[CUSTOM_SCHEMA], op.value[CUSTOM_SCHEMA]);
                if (!user.schemas.includes(CUSTOM_SCHEMA)) user.schemas.push(CUSTOM_SCHEMA);
                user.meta.lastModified = new Date().toISOString();
                changed = true;
                continue;
            }
```

The full loop body should now read (for reference, `routes/users.js:153-192` after this change):

```js
        for (const op of Operations) {
            if (!op.op || op.op.toLowerCase() !== 'replace') continue;

            // active: { op: "replace", path: "active", value: false }
            if (op.path === 'active') {
                user.active = op.value;
                user.meta.lastModified = new Date().toISOString();
                changed = true;
                continue;
            }

            // active: { op: "replace", value: { active: false } }  (Okta format)
            if (!op.path && typeof op.value === 'object' && 'active' in op.value) {
                user.active = op.value.active;
                user.meta.lastModified = new Date().toISOString();
                changed = true;
                continue;
            }

            // department path format: "urn:...:department"
            const deptPath = `${ENTERPRISE_SCHEMA}:department`;
            if (op.path === deptPath) {
                if (!user[ENTERPRISE_SCHEMA]) user[ENTERPRISE_SCHEMA] = {};
                user[ENTERPRISE_SCHEMA].department = op.value;
                if (!user.schemas.includes(ENTERPRISE_SCHEMA)) user.schemas.push(ENTERPRISE_SCHEMA);
                user.meta.lastModified = new Date().toISOString();
                changed = true;
                continue;
            }

            // department value object format: { op: "replace", value: { "urn:...": { "department": "Sales" } } }
            if (!op.path && typeof op.value === 'object' && op.value[ENTERPRISE_SCHEMA]) {
                if (!user[ENTERPRISE_SCHEMA]) user[ENTERPRISE_SCHEMA] = {};
                Object.assign(user[ENTERPRISE_SCHEMA], op.value[ENTERPRISE_SCHEMA]);
                if (!user.schemas.includes(ENTERPRISE_SCHEMA)) user.schemas.push(ENTERPRISE_SCHEMA);
                user.meta.lastModified = new Date().toISOString();
                changed = true;
                continue;
            }

            // customExt path format: "urn:...:customExt"
            const customExtPath = `${CUSTOM_SCHEMA}:customExt`;
            if (op.path === customExtPath) {
                if (!user[CUSTOM_SCHEMA]) user[CUSTOM_SCHEMA] = {};
                user[CUSTOM_SCHEMA].customExt = op.value;
                if (!user.schemas.includes(CUSTOM_SCHEMA)) user.schemas.push(CUSTOM_SCHEMA);
                user.meta.lastModified = new Date().toISOString();
                changed = true;
                continue;
            }

            // customExt value object format: { op: "replace", value: { "urn:...": { "customExt": "foo" } } }
            if (!op.path && typeof op.value === 'object' && op.value[CUSTOM_SCHEMA]) {
                if (!user[CUSTOM_SCHEMA]) user[CUSTOM_SCHEMA] = {};
                Object.assign(user[CUSTOM_SCHEMA], op.value[CUSTOM_SCHEMA]);
                if (!user.schemas.includes(CUSTOM_SCHEMA)) user.schemas.push(CUSTOM_SCHEMA);
                user.meta.lastModified = new Date().toISOString();
                changed = true;
                continue;
            }
        }
```

- [ ] **Step 2: Verify syntax**

Run: `node --check routes/users.js`
Expected: no output, exit code 0.

- [ ] **Step 3: Manual verification (requires a running server + DB)**

Using a user ID from Task 2's test (or any existing user):

```bash
curl -s -X PATCH http://localhost:3000/scim/v2/Users/<user-id> \
  -H "Authorization: Bearer $SCIM_ACCESS_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "Operations": [
      { "op": "replace", "path": "urn:ietf:params:scim:schemas:extension:custom:2.0:User:customExt", "value": "patched-value" }
    ]
  }' | jq .
```

Expected: `200`, response's custom extension object shows `customExt: "patched-value"`.

- [ ] **Step 4: Commit**

```bash
git add routes/users.js
git commit -m "feat: handle customExt on PATCH /scim/v2/Users"
```

---

### Task 4: Extend OAuth token lifetime to 90 days

**Files:**
- Modify: `server.js:160`, `server.js:170`

- [ ] **Step 1: Update client_credentials grant response**

Change (`server.js:160`):

```js
            return res.status(200).json({ access_token: SCIM_ACCESS_TOKEN, token_type: 'Bearer', expires_in: 3600 });
```

(the one inside the `if (grant_type === 'client_credentials')` block) to:

```js
            return res.status(200).json({ access_token: SCIM_ACCESS_TOKEN, token_type: 'Bearer', expires_in: 7776000 });
```

- [ ] **Step 2: Update authorization_code grant response**

Change (`server.js:170`):

```js
            return res.status(200).json({ access_token: SCIM_ACCESS_TOKEN, token_type: 'Bearer', expires_in: 3600 });
```

(the one inside the `if (grant_type === 'authorization_code')` block) to:

```js
            return res.status(200).json({ access_token: SCIM_ACCESS_TOKEN, token_type: 'Bearer', expires_in: 7776000 });
```

- [ ] **Step 3: Verify syntax**

Run: `node --check server.js`
Expected: no output, exit code 0.

- [ ] **Step 4: Manual verification (requires a running server)**

```bash
curl -s -X POST http://localhost:3000/token \
  -d "grant_type=client_credentials&client_id=$OAUTH_CLIENT_ID&client_secret=$OAUTH_CLIENT_SECRET" | jq .
```

Expected: `expires_in` is `7776000`.

- [ ] **Step 5: Commit**

```bash
git add server.js
git commit -m "feat: extend OAuth token lifetime to 90 days"
```

---

## Post-implementation (manual, outside this plan)

Per the design spec's open question: after deploying, re-run the Okta provisioning/import flow for this app and record whether the `ClassCastException` recurs now that `customExt` is listed in `/Schemas` without `schemaExtensions` wiring. This determines whether `/Schemas` listing alone is safe, informing whether the enterprise `department` extension can be safely re-added later.
