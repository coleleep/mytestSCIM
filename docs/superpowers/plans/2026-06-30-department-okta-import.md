# Department Attribute + Okta Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `department` via the SCIM enterprise extension schema to users, and advertise it so Okta Import can discover and map it.

**Architecture:** No DB changes needed — `scim_data` is JSONB and stores the enterprise extension block as a top-level key. POST/PUT/PATCH in `routes/users.js` are updated to read/write the extension. `server.js` gets a new `ENTERPRISE_USER_SCHEMA` constant added to `SCHEMAS`. The UI table gets a Department column.

**Tech Stack:** Node.js, Express, PostgreSQL (via `pg`), EJS templates, deployed on Render

---

## File Map

| File | Change |
|---|---|
| `routes/users.js` | Update POST, PUT, PATCH to handle enterprise extension |
| `server.js` | Add `ENTERPRISE_USER_SCHEMA`, add to `SCHEMAS` array |
| `views/users.ejs` | Add Department column to users table |

---

### Task 1: Update POST `/scim/v2/Users` to accept department

**Files:**
- Modify: `routes/users.js` (POST handler, ~line 66)

- [ ] **Step 1: Update the POST handler**

Replace the existing POST handler in `routes/users.js` with:

```js
const ENTERPRISE_SCHEMA = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

// POST /scim/v2/Users
router.post('/', async (req, res) => {
    const scimUser = req.body;
    if (!scimUser || !scimUser.userName) { return res.status(400).json({ detail: 'userName is required' }); }
    const userId = uuidv4();

    const enterpriseExt = scimUser[ENTERPRISE_SCHEMA];
    const schemas = ["urn:ietf:params:scim:schemas:core:2.0:User"];
    if (enterpriseExt) schemas.push(ENTERPRISE_SCHEMA);

    const newUser = {
        id: userId,
        schemas,
        userName: scimUser.userName,
        name: scimUser.name || {},
        emails: scimUser.emails || [],
        active: scimUser.active !== undefined ? scimUser.active : true,
        meta: {
            resourceType: "User",
            created: new Date().toISOString(),
            lastModified: new Date().toISOString(),
            location: `/scim/v2/Users/${userId}`
        }
    };
    if (enterpriseExt) newUser[ENTERPRISE_SCHEMA] = enterpriseExt;

    try {
        await pool.query(`INSERT INTO users (id, userName, active, scim_data) VALUES ($1, $2, $3, $4)`, [newUser.id, newUser.userName, newUser.active, newUser]);
        res.status(201).json(newUser);
    } catch (err) {
        if (err.code === '23505') { return res.status(409).json({ detail: 'userName must be unique.' }); }
        res.status(500).json({ detail: "Database insert error" });
    }
});
```

Note: Add the `ENTERPRISE_SCHEMA` constant at the top of the file, after the `pool` declaration.

- [ ] **Step 2: Verify the server starts without errors**

```bash
node server.js
```
Expected: `Server is running and ready on port 3000` (or your configured port). No syntax errors.

- [ ] **Step 3: Test POST with department**

```bash
curl -X POST http://localhost:3000/scim/v2/Users \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
    "userName": "test.dept@example.com",
    "name": { "givenName": "Test", "familyName": "Dept" },
    "emails": [{ "value": "test.dept@example.com", "type": "work", "primary": true }],
    "active": true,
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { "department": "Engineering" }
  }'
```

Expected: HTTP 201 with response body containing `"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { "department": "Engineering" }` and `schemas` array including both schema URIs.

- [ ] **Step 4: Test POST without department (backward compat)**

```bash
curl -X POST http://localhost:3000/scim/v2/Users \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "test.nodept@example.com",
    "active": true
  }'
```

Expected: HTTP 201, `schemas` array contains only `urn:ietf:params:scim:schemas:core:2.0:User`, no enterprise extension key in response.

- [ ] **Step 5: Commit**

```bash
git add routes/users.js
git commit -m "feat: accept department via enterprise extension on POST /Users"
```

---

### Task 2: Update PUT `/scim/v2/Users/:id` to handle department

**Files:**
- Modify: `routes/users.js` (PUT handler, ~line 81)

- [ ] **Step 1: Update the PUT handler**

Replace the existing PUT handler with:

```js
// PUT /scim/v2/Users/:id
router.put('/:id', async (req, res) => {
    const userId = req.params.id;
    const scimUser = req.body;
    let existingUser;
    try {
        const { rows } = await pool.query(`SELECT scim_data FROM users WHERE id = $1`, [userId]);
        if (rows.length === 0) { return res.status(404).json({ detail: "User not found" }); }
        existingUser = rows[0].scim_data;
    } catch (err) { return res.status(500).json({ detail: "Database query error on fetch" }); }

    const enterpriseExt = scimUser[ENTERPRISE_SCHEMA];
    const schemas = scimUser.schemas || ["urn:ietf:params:scim:schemas:core:2.0:User"];
    if (enterpriseExt && !schemas.includes(ENTERPRISE_SCHEMA)) schemas.push(ENTERPRISE_SCHEMA);
    if (!enterpriseExt) {
        const idx = schemas.indexOf(ENTERPRISE_SCHEMA);
        if (idx > -1) schemas.splice(idx, 1);
    }

    const updatedUser = {
        id: userId,
        schemas,
        userName: scimUser.userName,
        name: scimUser.name || {},
        emails: scimUser.emails || [],
        active: scimUser.active !== undefined ? scimUser.active : true,
        meta: { ...existingUser.meta, lastModified: new Date().toISOString(), location: `/scim/v2/Users/${userId}` }
    };
    if (enterpriseExt) updatedUser[ENTERPRISE_SCHEMA] = enterpriseExt;

    try {
        await pool.query(`UPDATE users SET userName = $1, active = $2, scim_data = $3 WHERE id = $4`, [updatedUser.userName, updatedUser.active, updatedUser, userId]);
        res.status(200).json(updatedUser);
    } catch (err) {
        if (err.code === '23505') { return res.status(409).json({ detail: 'userName must be unique.' }); }
        res.status(500).json({ detail: "Database error on update" });
    }
});
```

- [ ] **Step 2: Test PUT with department**

Use the `id` from the user created in Task 1, Step 3:

```bash
curl -X PUT http://localhost:3000/scim/v2/Users/<id-from-task-1> \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
    "userName": "test.dept@example.com",
    "name": { "givenName": "Test", "familyName": "Dept" },
    "emails": [{ "value": "test.dept@example.com", "type": "work", "primary": true }],
    "active": true,
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { "department": "Sales" }
  }'
```

Expected: HTTP 200, `department` is now `"Sales"`.

- [ ] **Step 3: Test PUT removing department**

```bash
curl -X PUT http://localhost:3000/scim/v2/Users/<id-from-task-1> \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "test.dept@example.com",
    "active": true
  }'
```

Expected: HTTP 200, no enterprise extension key in response, `schemas` only has core URI.

- [ ] **Step 4: Commit**

```bash
git add routes/users.js
git commit -m "feat: handle department via enterprise extension on PUT /Users/:id"
```

---

### Task 3: Update PATCH `/scim/v2/Users/:id` to handle department

**Files:**
- Modify: `routes/users.js` (PATCH handler, ~line 101)

- [ ] **Step 1: Update the PATCH handler**

Replace the existing PATCH handler with:

```js
// PATCH /scim/v2/Users/:id
router.patch('/:id', async (req, res) => {
    const userId = req.params.id;
    const { Operations } = req.body;
    if (!Operations) { return res.status(400).json({ detail: "PATCH request must contain 'Operations'" }); }

    try {
        const { rows } = await pool.query(`SELECT scim_data FROM users WHERE id = $1`, [userId]);
        if (rows.length === 0) { return res.status(404).json({ detail: "User not found" }); }
        const user = rows[0].scim_data;
        let changed = false;

        for (const op of Operations) {
            if (op.op.toLowerCase() !== 'replace') continue;

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
        }

        if (changed) {
            await pool.query(`UPDATE users SET active = $1, scim_data = $2 WHERE id = $3`, [user.active, user, userId]);
            return res.status(200).json(user);
        }
        res.status(204).send();
    } catch (err) { return res.status(500).json({ detail: "Database error" }); }
});
```

- [ ] **Step 2: Test PATCH with path format**

```bash
curl -X PATCH http://localhost:3000/scim/v2/Users/<id-from-task-1> \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [{
      "op": "replace",
      "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
      "value": "Marketing"
    }]
  }'
```

Expected: HTTP 200, `department` is `"Marketing"`.

- [ ] **Step 3: Test PATCH with value object format (Okta's format)**

```bash
curl -X PATCH http://localhost:3000/scim/v2/Users/<id-from-task-1> \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [{
      "op": "replace",
      "value": {
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { "department": "HR" }
      }
    }]
  }'
```

Expected: HTTP 200, `department` is `"HR"`.

- [ ] **Step 4: Test PATCH active still works**

```bash
curl -X PATCH http://localhost:3000/scim/v2/Users/<id-from-task-1> \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [{ "op": "replace", "path": "active", "value": false }]
  }'
```

Expected: HTTP 200, `active` is `false`, `department` unchanged.

- [ ] **Step 5: Commit**

```bash
git add routes/users.js
git commit -m "feat: handle department via enterprise extension on PATCH /Users/:id"
```

---

### Task 4: Advertise enterprise schema in server.js

**Files:**
- Modify: `server.js` (~line 42, near `USER_SCHEMA` and `SCHEMAS`)

- [ ] **Step 1: Add ENTERPRISE_USER_SCHEMA constant**

In `server.js`, after the `GROUP_SCHEMA` constant declaration, add:

```js
const ENTERPRISE_USER_SCHEMA = {
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
};
```

- [ ] **Step 2: Add to SCHEMAS array**

Change the existing `SCHEMAS` line from:

```js
const SCHEMAS = [USER_SCHEMA, GROUP_SCHEMA];
```

to:

```js
const SCHEMAS = [USER_SCHEMA, GROUP_SCHEMA, ENTERPRISE_USER_SCHEMA];
```

- [ ] **Step 3: Verify /scim/v2/Schemas returns enterprise schema**

```bash
curl http://localhost:3000/scim/v2/Schemas \
  -H "Authorization: Bearer <your-token>"
```

Expected: JSON with `Resources` array containing three entries — the User schema, Group schema, and the enterprise schema with `id: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"` and `department` in its `attributes`.

- [ ] **Step 4: Commit**

```bash
git add server.js
git commit -m "feat: advertise enterprise user schema with department in /scim/v2/Schemas"
```

---

### Task 5: Add Department column to UI

**Files:**
- Modify: `views/users.ejs`

- [ ] **Step 1: Add Department column header**

In `views/users.ejs`, find the `<thead>` row and add a `Department` header after `Full Name` and before `Email`:

```html
<thead>
    <tr>
        <th>ID</th>
        <th>Username</th>
        <th>Full Name</th>
        <th style="white-space: nowrap;">Department</th>
        <th>Email</th>
        <th>Status</th>
    </tr>
</thead>
```

- [ ] **Step 2: Add Department data cell**

In the `<tbody>` user row, add the department `<td>` after the Full Name cell and before the Email cell:

```html
<tr>
    <td><code class="code"><%= user.id %></code></td>
    <td><%= user.userName %></td>
    <td><%= (user.name && user.name.formatted) ? user.name.formatted : (user.name && user.name.givenName ? `${user.name.givenName} ${user.name.familyName || ''}`.trim() : 'N/A') %></td>
    <td style="white-space: nowrap;"><%= (user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'] && user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].department) ? user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'].department : 'N/A' %></td>
    <td><%= user.emails && user.emails[0] ? user.emails[0].value : 'N/A' %></td>
    <td><%= user.active ? 'Active' : 'Inactive' %></td>
</tr>
```

- [ ] **Step 3: Update the "no users" colspan**

Find the empty state row and update colspan from `5` to `6`:

```html
<td colspan="6" class="no-users">No users found. Try creating one via the API.</td>
```

- [ ] **Step 4: Verify in browser**

Start the server and navigate to `/ui/users`. Confirm:
- Department column is visible
- Users with department show the value
- Users without department show `N/A`
- Table fits without horizontal overflow on a normal browser window, scrolls cleanly when narrow

- [ ] **Step 5: Commit**

```bash
git add views/users.ejs
git commit -m "feat: add Department column to users UI"
```
