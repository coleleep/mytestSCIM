// server.js (Final version with correct middleware order)

import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import pg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';
import morgan from 'morgan';

// --- Setup for ES Modules ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const API_TOKEN = process.env.API_TOKEN || "secret-token-for-okta";

// --- Database Setup ---
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
pool.query('SELECT NOW()', (err, res) => {
    if (err) { console.error("Error connecting to the database:", err.message); }
    else {
        console.log("Connected to Postgres database successfully.");
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
const PORT = process.env.PORT || 3000;

// --- CORRECTED GLOBAL MIDDLEWARE SETUP ---
// These will run on EVERY request that comes into the app.
app.use(morgan('dev'));  // 1. Log a one-line summary of the request
app.use(express.json({ type: ['application/json', 'application/scim+json'] }));

// ------------------------------------

const detailedLogger = (req, res, next) => {
  console.log('--- New SCIM Request ---');
  console.log(`--> ${req.method} ${req.originalUrl}`);
  console.log('Request Headers:', JSON.stringify(req.headers, null, 2));
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Request Body:', JSON.stringify(req.body, null, 2));
  }
  const originalJson = res.json;
  res.json = function(body) {
    console.log(`<-- ${res.statusCode} ${req.method} ${req.originalUrl}`);
    console.log('Response Body:', JSON.stringify(body, null, 2));
    console.log('--- End SCIM Request ---');
    return originalJson.call(this, body);
  };
  const originalSend = res.send;
  res.send = function(body) {
      if(res.statusCode !== 204) {
        console.log(`<-- ${res.statusCode} ${req.method} ${req.originalUrl}`);
        console.log('Response Body:', body);
      } else { console.log(`<-- 204 No Content`); }
      console.log('--- End SCIM Request ---');
      return originalSend.call(this, body);
  };
  next();
};

const scimAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || authHeader !== `Bearer ${API_TOKEN}`) {
        return res.status(401).json({ schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], detail: "Unauthorized" });
    }
    next();
};

// --- ROUTER SETUP ---
const scimRouter = express.Router();
scimRouter.use(detailedLogger);   // 1. Use our detailed logger for SCIM routes
scimRouter.use(scimAuth);         // 2. Authenticate SCIM routes
app.use('/scim/v2', scimRouter);

// Set up UI routes on the main app
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// === SCIM API Endpoints (Attached to scimRouter) ===
// ... (All your scimRouter.get, .post, .put, etc. routes are unchanged) ...
scimRouter.get('/ServiceProviderConfig', (req, res) => res.json(SERVICE_PROVIDER_CONFIG));
scimRouter.get('/ResourceTypes', (req, res) => res.json({ Resources: [USER_RESOURCE_TYPE] }));
scimRouter.get('/Schemas', (req, res) => res.json({ Resources: SCHEMAS }));
scimRouter.get('/Users', async (req, res) => {
    try {
        let sql = `SELECT scim_data FROM users`;
        let params = [];
        if (req.query.filter) {
            const [attribute, operator, value] = req.query.filter.split(' ');
            if (attribute.toLowerCase() === 'username' && operator.toLowerCase() === 'eq') {
                sql += ' WHERE userName = $1';
                params.push(value.replace(/"/g, ''));
            }
        }
        const { rows } = await pool.query(sql, params);
        const resources = rows.map(row => row.scim_data);
        res.json({ schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], totalResults: resources.length, Resources: resources });
    } catch (err) { res.status(500).json({ detail: "Database query error" }); }
});
scimRouter.get('/Users/:id', async (req, res) => {
    try {
        const { rows } = await pool.query(`SELECT scim_data FROM users WHERE id = $1`, [req.params.id]);
        if (rows.length === 0) { return res.status(404).json({ detail: "User not found" }); }
        res.status(200).json(rows[0].scim_data);
    } catch (err) { res.status(500).json({ detail: "Database query error" }); }
});
scimRouter.post('/Users', async (req, res) => {
    const scimUser = req.body; 
    if (!scimUser || !scimUser.userName) { return res.status(400).json({ detail: 'userName is required' }); }
    const userId = uuidv4();
    const newUser = { id: userId, schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: scimUser.userName, name: scimUser.name || {}, emails: scimUser.emails || [], active: scimUser.active !== undefined ? scimUser.active : true, meta: { resourceType: "User", created: new Date().toISOString(), lastModified: new Date().toISOString(), location: `/scim/v2/Users/${userId}` } };
    try {
        const sql = `INSERT INTO users (id, userName, active, scim_data) VALUES ($1, $2, $3, $4)`;
        await pool.query(sql, [newUser.id, newUser.userName, newUser.active, newUser]);
        res.status(201).json(newUser);
    } catch (err) {
        if (err.code === '23505') { return res.status(409).json({ detail: 'userName must be unique.' }); }
        res.status(500).json({ detail: "Database insert error" });
    }
});
scimRouter.put('/Users/:id', async (req, res) => {
    const userId = req.params.id;
    const scimUser = req.body;
    let existingUser;
    try {
        const { rows } = await pool.query(`SELECT scim_data FROM users WHERE id = $1`, [userId]);
        if (rows.length === 0) { return res.status(404).json({ detail: "User not found" }); }
        existingUser = rows[0].scim_data;
    } catch (err) { return res.status(500).json({ detail: "Database query error on fetch" }); }
    const updatedUser = { id: userId, schemas: scimUser.schemas || existingUser.schemas, userName: scimUser.userName, name: scimUser.name || {}, emails: scimUser.emails || [], active: scimUser.active !== undefined ? scimUser.active : true, meta: { ...existingUser.meta, lastModified: new Date().toISOString(), location: `/scim/v2/Users/${userId}` } };
    try {
        const sql = `UPDATE users SET userName = $1, active = $2, scim_data = $3 WHERE id = $4`;
        await pool.query(sql, [updatedUser.userName, updatedUser.active, updatedUser, userId]);
        res.status(200).json(updatedUser);
    } catch (err) {
        if (err.code === '23505') { return res.status(409).json({ detail: 'userName must be unique.' }); }
        res.status(500).json({ detail: "Database error on update" });
    }
});
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
scimRouter.delete('/Users/:id', async (req, res) => {
    try {
        const result = await pool.query(`DELETE FROM users WHERE id = $1`, [req.params.id]);
        if (result.rowCount === 0) { return res.status(404).json({ detail: "User not found" }); }
        res.status(204).send();
    } catch (err) { res.status(500).json({ detail: "Database error" }); }
});

// === Web Interface Endpoints ===
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
    console.log(`Server is running and listening on port ${PORT}`);
    console.log(`SCIM Bearer Token: ${API_TOKEN}`);
});
