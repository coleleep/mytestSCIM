// server.js (Final version with GUARANTEED logging order)

import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import pg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';
import morgan from 'morgan';
import session from 'express-session';
import OktaOidc from '@okta/oidc-middleware';
const { ExpressOIDC } = OktaOidc;

// --- Setup for ES Modules ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Configuration ---
const OKTA_ORG_URL = process.env.OKTA_ORG_URL || 'https://YOUR_OKTA_DOMAIN';
const OKTA_CLIENT_ID = process.env.OKTA_CLIENT_ID || '{YourOktaClientID}';
const OKTA_CLIENT_SECRET = process.env.OKTA_CLIENT_SECRET || '{YourOktaClientSecret}';
const APP_SECRET = process.env.APP_SECRET || 'a-long-random-string-you-should-change';
const API_TOKEN = process.env.API_TOKEN || "secret-token-for-okta";

const app = express();
const PORT = process.env.PORT || 3000;

// --- Database Setup (No changes) ---
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

// --- SCIM Objects (No changes) ---
const USER_SCHEMA = { "id": "urn:ietf:params:scim:schemas:core:2.0:User", "name": "User", "description": "User Account", "attributes": [ { "name": "userName", "type": "string", "multiValued": false, "description": "Unique identifier for the User.", "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server" }, { "name": "name", "type": "complex", "multiValued": false, "description": "The components of the user's real name.", "required": false, "subAttributes": [ { "name": "formatted", "type": "string", "multiValued": false, "description": "The full name, including all middle names, titles, and suffixes.", "required": false, "mutability": "readWrite", "returned": "default" }, { "name": "familyName", "type": "string", "multiValued": false, "description": "The family name of the User.", "required": false, "mutability": "readWrite", "returned": "default" }, { "name": "givenName", "type": "string", "multiValued": false, "description": "The given name of the User.", "required": false, "mutability": "readWrite", "returned": "default" } ]}, { "name": "displayName", "type": "string", "multiValued": false, "description": "The name of the User, suitable for display to end-users.", "required": false, "mutability": "readWrite", "returned": "default" }, { "name": "emails", "type": "complex", "multiValued": true, "description": "Email addresses for the user.", "required": false, "subAttributes": [ { "name": "value", "type": "string", "multiValued": false, "description": "Email address for the user.", "required": false, "mutability": "readWrite", "returned": "default" }, { "name": "type", "type": "string", "multiValued": false, "description": "A label indicating the attribute's function.", "required": false, "canonicalValues": ["work", "home", "other"], "mutability": "readWrite", "returned": "default" }, { "name": "primary", "type": "boolean", "multiValued": false, "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute.", "required": false, "mutability": "readWrite", "returned": "default" } ]}, { "name": "active", "type": "boolean", "multiValued": false, "description": "A Boolean value indicating the user's administrative status.", "required": false, "mutability": "readWrite", "returned": "default" } ], "meta": { "resourceType": "Schema", "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User" } };
const GROUP_SCHEMA = { "id": "urn:ietf:params:scim:schemas:core:2.0:Group", "name": "Group", "description": "Group", "attributes": [ { "name": "displayName", "type": "string", "multiValued": false, "description": "A human-readable name for the Group.", "required": true, "mutability": "readWrite", "returned": "default" }, { "name": "members", "type": "complex", "multiValued": true, "description": "A list of members of the Group.", "required": false, "mutability": "readWrite", "returned": "default", "subAttributes": [ { "name": "value", "type": "string", "multiValued": false, "description": "Identifier of the member of this Group.", "required": false, "mutability": "immutable", "returned": "default" }, { "name": "$ref", "type": "reference", "multiValued": false, "description": "The URI of the corresponding 'User' resource.", "required": false, "mutability": "immutable", "returned": "default" }, { "name": "display", "type": "string", "multiValued": false, "description": "A human-readable name for the member.", "required": false, "mutability": "immutable", "returned": "default" } ]} ], "meta": { "resourceType": "Schema", "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group" }};
const SCHEMAS = [USER_SCHEMA, GROUP_SCHEMA];
const SERVICE_PROVIDER_CONFIG = { "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"], "documentationUri": "http://example.com/help/scim.html", "patch": { "supported": true }, "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 }, "filter": { "supported": true, "maxResults": 100 }, "changePassword": { "supported": false }, "sort": { "supported": false }, "etag": { "supported": false }, "authenticationSchemes": [ { "name": "OAuth Bearer Token", "description": "Authentication scheme using the OAuth Bearer Token standard.", "specUri": "http://www.rfc-editor.org/info/rfc6750", "type": "oauthbearertoken", "primary": true } ], "meta": { "location": "/scim/v2/ServiceProviderConfig", "resourceType": "ServiceProviderConfig" } };
const USER_RESOURCE_TYPE = { "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User", "endpoint": "/scim/v2/Users", "description": "User Account", "schema": "urn:ietf:params:scim:schemas:core:2.0:User", "meta": { "location": "/scim/v2/ResourceTypes/User", "resourceType": "ResourceType" } };

// --- Detailed Logging Middleware ---
const detailedLogger = (req, res, next) => {
    // Only log in detail for SCIM requests
    if (req.originalUrl.startsWith('/scim/v2')) {
      console.log('--- New SCIM Request ---');
      console.log(`--> ${req.method} ${req.originalUrl}`);
      console.log('Request Headers:', JSON.stringify(req.headers, null, 2));
      
      // This check will now work because express.json() has already run
      if (req.body && Object.keys(req.body).length > 0) {
        console.log('Request Body:', JSON.stringify(req.body, null, 2));
      }
      
      // Intercept the response to log it
      const originalJson = res.json;
      res.json = function(body) {
        console.log(`<-- ${res.statusCode} ${req.method} ${req.originalUrl}`);
        console.log('Response Body:', JSON.stringify(body, null, 2));
        console.log('--- End SCIM Request ---');
        return originalJson.call(this, body);
      };
    }
    next();
};

// --- Authentication Middleware ---
const scimAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || authHeader !== `Bearer ${API_TOKEN}`) {
        return res.status(401).json({ detail: "Unauthorized" });
    }
    next();
};

// --- GLOBAL APP SETUP ---
app.use(morgan('dev')); // 1. Use morgan for one-line summaries on ALL requests
app.use(express.json({ type: ['application/json', 'application/scim+json'] })); // 2. CRITICAL: Parse body for SCIM content-type on ALL requests
app.use(detailedLogger); // 3. Use our detailed logger on ALL requests (it will self-filter for SCIM)

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({ secret: APP_SECRET, resave: false, saveUninitialized: true }));
const oidc = new ExpressOIDC({
  issuer: `${OKTA_ORG_URL}/oauth2/default`,
  client_id: OKTA_CLIENT_ID,
  client_secret: OKTA_CLIENT_SECRET,
  appBaseUrl: process.env.BASE_URL || `http://localhost:${PORT}`,
  scope: 'openid profile',
  routes: { login: { path: '/login' }, callback: { path: '/authorization-code/callback' } }
});
app.use(oidc.router);


// --- ROUTER SETUP ---
const scimRouter = express.Router();
// The router now only needs the middleware specific to its routes (authentication)
scimRouter.use(scimAuth);
app.use('/scim/v2', scimRouter);


// === SCIM API Endpoints (Attached to scimRouter) ===
scimRouter.get('/ServiceProviderConfig', (req, res) => res.json(SERVICE_PROVIDER_CONFIG));
scimRouter.get('/ResourceTypes', (req, res) => res.json({ Resources: [USER_RESOURCE_TYPE] }));
scimRouter.get('/Schemas', (req, res) => res.json({ Resources: SCHEMAS }));
scimRouter.get('/Users', async (req, res) => {
    try {
        const startIndex = parseInt(req.query.startIndex, 10) || 1;
        const count = parseInt(req.query.count, 10) || 100;
        const filter = req.query.filter;
        let queryParams = [];
        let filterClause = '';
        if (filter) {
            const [attribute, operator, value] = filter.split(' ');
            if (attribute.toLowerCase() === 'username' && operator.toLowerCase() === 'eq') {
                filterClause = 'WHERE userName = $1';
                queryParams.push(value.replace(/"/g, ''));
            }
        }
        const totalResultPromise = pool.query(`SELECT COUNT(*) AS total FROM users ${filterClause}`, queryParams);
        const usersPromise = pool.query(`SELECT scim_data FROM users ${filterClause} ORDER BY userName LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`, [...queryParams, count, startIndex - 1]);
        const [totalResult, usersResult] = await Promise.all([totalResultPromise, usersPromise]);
        const totalResults = parseInt(totalResult.rows[0].total, 10);
        const resources = usersResult.rows.map(row => row.scim_data);
        res.json({ schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], totalResults, itemsPerPage: resources.length, startIndex, Resources: resources });
    } catch (err) {
        console.error("Error in GET /Users:", err);
        res.status(500).json({ detail: "Database query error" });
    }
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
app.get('/', (req, res) => {
  if (req.userContext) { res.redirect('/ui/users'); }
  else { res.redirect('/login'); }
});
app.get('/login', (req, res) => {
  res.render('login', { oktaOrgUrl: OKTA_ORG_URL, oktaClientId: OKTA_CLIENT_ID });
});
app.get('/ui/users', oidc.ensureAuthenticated(), async (req, res) => {
    try {
        const { rows } = await pool.query(`SELECT scim_data FROM users`);
        const users = rows.map(row => row.scim_data);
        res.render('users', { users: users, user: req.userContext.userinfo });
    } catch (err) { res.status(500).send("Error retrieving users."); }
});


// --- Server Start ---
app.listen(PORT, () => {
    console.log(`Server is running and listening on port ${PORT}`);
});