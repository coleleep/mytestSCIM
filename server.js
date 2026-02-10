// server.js (UPDATED for Postgres and Render)

import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import pg from 'pg'; // UPDATED: Import pg
import path from 'path';
import { fileURLToPath } from 'url';

// --- Setup for ES Modules ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const API_TOKEN = process.env.API_TOKEN || "secret-token-for-okta"; // Use environment variable

// --- UPDATED: Database Setup for Postgres ---
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // This will be provided by Render
  ssl: {
    rejectUnauthorized: false // Required for connecting to Neon
  }
});

// Test the database connection
pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error("Error connecting to the database:", err.message);
    } else {
        console.log("Connected to Postgres database successfully.");
        // Create table if it doesn't exist
        pool.query(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, userName TEXT UNIQUE, active BOOLEAN, scim_data JSONB)`, (err, res) => {
            if (err) { console.error("Error creating table:", err) }
        });
    }
});

// --- SCIM Schema and Discovery Objects (No Changes) ---
const USER_SCHEMA = { "id": "urn:ietf:params:scim:schemas:core:2.0:User", "name": "User", "description": "User Account", "attributes": [ { "name": "userName", "type": "string", "multiValued": false, "description": "Unique identifier for the User.", "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server" }, { "name": "name", "type": "complex", "multiValued": false, "description": "The components of the user's real name.", "required": false, "subAttributes": [ { "name": "formatted", "type": "string", "multiValued": false, "description": "The full name, including all middle names, titles, and suffixes.", "required": false, "mutability": "readWrite", "returned": "default" }, { "name": "familyName", "type": "string", "multiValued": false, "description": "The family name of the User.", "required": false, "mutability": "readWrite", "returned": "default" }, { "name": "givenName", "type": "string", "multiValued": false, "description": "The given name of the User.", "required": false, "mutability": "readWrite", "returned": "default" } ]}, { "name": "displayName", "type": "string", "multiValued": false, "description": "The name of the User, suitable for display to end-users.", "required": false, "mutability": "readWrite", "returned": "default" }, { "name": "emails", "type": "complex", "multiValued": true, "description": "Email addresses for the user.", "required": false, "subAttributes": [ { "name": "value", "type": "string", "multiValued": false, "description": "Email address for the user.", "required": false, "mutability": "readWrite", "returned": "default" }, { "name": "type", "type": "string", "multiValued": false, "description": "A label indicating the attribute's function.", "required": false, "canonicalValues": ["work", "home", "other"], "mutability": "readWrite", "returned": "default" }, { "name": "primary", "type": "boolean", "multiValued": false, "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute.", "required": false, "mutability": "readWrite", "returned": "default" } ]}, { "name": "active", "type": "boolean", "multiValued": false, "description": "A Boolean value indicating the user's administrative status.", "required": false, "mutability": "readWrite", "returned": "default" } ], "meta": { "resourceType": "Schema", "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User" } };
const GROUP_SCHEMA = { "id": "urn:ietf:params:scim:schemas:core:2.0:Group", "name": "Group", "description": "Group", "attributes": [ { "name": "displayName", "type": "string", "multiValued": false, "description": "A human-readable name for the Group.", "required": true, "mutability": "readWrite", "returned": "default" }, { "name": "members", "type": "complex", "multiValued": true, "description": "A list of members of the Group.", "required": false, "mutability": "readWrite", "returned": "default", "subAttributes": [ { "name": "value", "type": "string", "multiValued": false, "description": "Identifier of the member of this Group.", "required": false, "mutability": "immutable", "returned": "default" }, { "name": "$ref", "type": "reference", "multiValued": false, "description": "The URI of the corresponding 'User' resource.", "required": false, "mutability": "immutable", "returned": "default" }, { "name": "display", "type": "string", "multiValued": false, "description": "A human-readable name for the member.", "required": false, "mutability": "immutable", "returned": "default" } ]} ], "meta": { "resourceType": "Schema", "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group" }};
const SCHEMAS = [USER_SCHEMA, GROUP_SCHEMA];
const SERVICE_PROVIDER_CONFIG = { "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"], "documentationUri": "http://example.com/help/scim.html", "patch": { "supported": true }, "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 }, "filter": { "supported": true, "maxResults": 100 }, "changePassword": { "supported": false }, "sort": { "supported": false }, "etag": { "supported": false }, "authenticationSchemes": [ { "name": "OAuth Bearer Token", "description": "Authentication scheme using the OAuth Bearer Token standard.", "specUri": "http://www.rfc-editor.org/info/rfc6750", "type": "oauthbearertoken", "primary": true } ], "meta": { "location": "/scim/v2/ServiceProviderConfig", "resourceType": "ServiceProviderConfig" } };
const USER_RESOURCE_TYPE = { "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User", "endpoint": "/scim/v2/Users", "description": "User Account", "schema": "urn:ietf:params:scim:schemas:core:2.0:User", "meta": { "location": "/scim/v2/ResourceTypes/User", "resourceType": "ResourceType" } };

const app = express();
const PORT = process.env.PORT || 3000; // Render provides the PORT env var

// --- Middleware & View Engine (No Changes) ---
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
const scimAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || authHeader !== `Bearer ${API_TOKEN}`) {
        return res.status(401).json({ schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], detail: "Unauthorized" });
    }
    next();
};
const scimRouter = express.Router();
scimRouter.use(scimAuth);
app.use('/scim/v2', scimRouter);

// === SCIM API Endpoints (UPDATED for Postgres) ===

// Discovery Endpoints (No change)
scimRouter.get('/ServiceProviderConfig', (req, res) => res.json(SERVICE_PROVIDER_CONFIG));
scimRouter.get('/ResourceTypes', (req, res) => res.json({ Resources: [USER_RESOURCE_TYPE] }));
scimRouter.get('/Schemas', (req, res) => res.json({ Resources: SCHEMAS }));

// Get User(s) with Filtering
scimRouter.get('/Users', async (req, res) => {
    try {
        let sql = `SELECT scim_data FROM users`;
        let params = [];
        if (req.query.filter) {
            const [attribute, operator, value] = req.query.filter.split(' ');
            if (attribute.toLowerCase() === 'username' && operator.toLowerCase() === 'eq') {
                sql += ' WHERE userName = $1'; // Use $1 for Postgres
                params.push(value.replace(/"/g, ''));
            }
        }
        const { rows } = await pool.query(sql, params);
        const resources = rows.map(row => row.scim_data);
        res.json({ schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], totalResults: resources.length, Resources: resources });
    } catch (err) { res.status(500).json({ detail: "Database query error" }); }
});

// Get a single user by ID
scimRouter.get('/Users/:id', async (req, res) => {
    try {
        const { rows } = await pool.query(`SELECT scim_data FROM users WHERE id = $1`, [req.params.id]);
        if (rows.length === 0) { return res.status(404).json({ detail: "User not found" }); }
        res.status(200).json(rows[0].scim_data);
    } catch (err) { res.status(500).json({ detail: "Database query error" }); }
});

// Create User
scimRouter.post('/Users', async (req, res) => {
    const scimUser = req.body;
    if (!scimUser.userName) { return res.status(400).json({ detail: 'userName is required' }); }
    const userId = uuidv4();
    const newUser = { id: userId, schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: scimUser.userName, name: scimUser.name || {}, emails: scimUser.emails || [], active: scimUser.active !== undefined ? scimUser.active : true, meta: { resourceType: "User", created: new Date().toISOString(), lastModified: new Date().toISOString(), location: `/scim/v2/Users/${userId}` } };
    try {
        const sql = `INSERT INTO users (id, userName, active, scim_data) VALUES ($1, $2, $3, $4)`;
        await pool.query(sql, [newUser.id, newUser.userName, newUser.active, newUser]);
        res.status(201).json(newUser);
    } catch (err) {
        if (err.code === '23505') { // Postgres unique violation code
            return res.status(409).json({ detail: 'userName must be unique.' });
        }
        res.status(500).json({ detail: "Database insert error" });
    }
});

// Update User (PUT)
scimRouter.put('/Users/:id', async (req, res) => {
    const userId = req.params.id;
    const scimUser = req.body;
    const updatedUser = { ...scimUser, id: userId, meta: { resourceType: "User", lastModified: new Date().toISOString(), location: `/scim/v2/Users/${userId}` } };
    try {
        const sql = `UPDATE users SET userName = $1, active = $2, scim_data = $3 WHERE id = $4`;
        const result = await pool.query(sql, [updatedUser.userName, updatedUser.active, updatedUser, userId]);
        if (result.rowCount === 0) { return res.status(404).json({ detail: "User not found" }); }
        res.status(200).json(updatedUser);
    } catch (err) { res.status(500).json({ detail: "Database error" }); }
});

// Patch User
scimRouter.patch('/Users/:id', async (req, res) => {
    const userId = req.params.id;
    const patchOps = req.body.Operations;
    if (!patchOps) { return res.status(400).json({ detail: "PATCH request must contain 'Operations'" }); }
    const activeOp = patchOps.find(op => op.op.toLowerCase() === 'replace' && op.path === 'active');
    if (activeOp) {
        const newActiveStatus = activeOp.value;
        try {
            const { rows } = await pool.query(`SELECT scim_data FROM users WHERE id = $1`, [userId]);
            if (rows.length === 0) { return res.status(404).json({ detail: "User not found" }); }
            const user = rows[0].scim_data;
            user.active = newActiveStatus;
            user.meta.lastModified = new Date().toISOString();
            await pool.query(`UPDATE users SET active = $1, scim_data = $2 WHERE id = $3`, [newActiveStatus, user, userId]);
            return res.status(200).json(user);
        } catch (err) { return res.status(500).json({ detail: "Database error" }); }
    }
    res.status(204).send();
});

// Delete User
scimRouter.delete('/Users/:id', async (req, res) => {
    try {
        const result = await pool.query(`DELETE FROM users WHERE id = $1`, [req.params.id]);
        if (result.rowCount === 0) { return res.status(404).json({ detail: "User not found" }); }
        res.status(204).send();
    } catch (err) { res.status(500).json({ detail: "Database error" }); }
});

// === Web Interface (UPDATED) ===
app.get('/', (req, res) => res.redirect('/ui/users'));
app.get('/ui/users', async (req, res) => {
    try {
        const { rows } = await pool.query(`SELECT scim_data FROM users`);
        const users = rows.map(row => row.scim_data);
        res.render('users', { users: users });
    } catch (err) { res.status(500).send("Error retrieving users."); }
});

// --- Server Start ---
app.listen(PORT, () => {
    console.log(`Server is running and listening on http://localhost:${PORT}`);
});
