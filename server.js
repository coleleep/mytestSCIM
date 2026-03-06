import express from 'express';
import pg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';
import morgan from 'morgan';
import session from 'express-session';
import crypto from 'crypto';
import OktaOidc from '@okta/oidc-middleware';
const { ExpressOIDC } = OktaOidc;

import usersRouter from './routes/users.js';
import groupsRouter from './routes/groups.js';

// --- Configuration ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const OKTA_ORG_URL = process.env.OKTA_ORG_URL;
const OKTA_CLIENT_ID_UI = process.env.OKTA_CLIENT_ID_UI;
const OKTA_CLIENT_SECRET_UI = process.env.OKTA_CLIENT_SECRET_UI;
const APP_SECRET = process.env.APP_SECRET;
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID;
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;
const SCIM_ACCESS_TOKEN = process.env.SCIM_ACCESS_TOKEN || `tok-${crypto.randomBytes(24).toString('hex')}`;

const app = express();
const PORT = process.env.PORT || 3000;

const authCodes = new Map();

// --- Database Pool Setup ---
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// --- SCIM Discovery Objects ---
const USER_SCHEMA = { "id": "urn:ietf:params:scim:schemas:core:2.0:User", "name": "User", "description": "User Account", "attributes": [ { "name": "userName", "type": "string", "multiValued": false, "description": "Unique identifier for the User.", "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server" }, { "name": "name", "type": "complex", "multiValued": false, "description": "The components of the user's real name.", "required": false, "subAttributes": [ { "name": "formatted", "type": "string", "multiValued": false, "description": "The full name, including all middle names, titles, and suffixes.", "required": false, "mutability": "readWrite", "returned": "default" }, { "name": "familyName", "type": "string", "multiValued": false, "description": "The family name of the User.", "required": false, "mutability": "readWrite", "returned": "default" }, { "name": "givenName", "type": "string", "multiValued": false, "description": "The given name of the User.", "required": false, "mutability": "readWrite", "returned": "default" } ]}, { "name": "displayName", "type": "string", "multiValued": false, "description": "The name of the User, suitable for display to end-users.", "required": false, "mutability": "readWrite", "returned": "default" }, { "name": "emails", "type": "complex", "multiValued": true, "description": "Email addresses for the user.", "required": false, "subAttributes": [ { "name": "value", "type": "string", "multiValued": false, "description": "Email address for the user.", "required": false, "mutability": "readWrite", "returned": "default" }, { "name": "type", "type": "string", "multiValued": false, "description": "A label indicating the attribute's function.", "required": false, "canonicalValues": ["work", "home", "other"], "mutability": "readWrite", "returned": "default" }, { "name": "primary", "type": "boolean", "multiValued": false, "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute.", "required": false, "mutability": "readWrite", "returned": "default" } ]}, { "name": "active", "type": "boolean", "multiValued": false, "description": "A Boolean value indicating the user's administrative status.", "required": false, "mutability": "readWrite", "returned": "default" } ], "meta": { "resourceType": "Schema", "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User" } };
const GROUP_SCHEMA = { "id": "urn:ietf:params:scim:schemas:core:2.0:Group", "name": "Group", "description": "Group", "attributes": [ { "name": "displayName", "type": "string", "multiValued": false, "description": "A human-readable name for the Group.", "required": true, "mutability": "readWrite", "returned": "default" }, { "name": "members", "type": "complex", "multiValued": true, "description": "A list of members of the Group.", "required": false, "mutability": "readWrite", "returned": "default", "subAttributes": [ { "name": "value", "type": "string", "multiValued": false, "description": "Identifier of the member of this Group.", "required": false, "mutability": "immutable", "returned": "default" }, { "name": "$ref", "type": "reference", "multiValued": false, "description": "The URI of the corresponding 'User' resource.", "required": false, "mutability": "immutable", "returned": "default" }, { "name": "display", "type": "string", "multiValued": false, "description": "A human-readable name for the member.", "required": false, "mutability": "immutable", "returned": "default" } ]} ], "meta": { "resourceType": "Schema", "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group" }};
const SCHEMAS = [USER_SCHEMA, GROUP_SCHEMA];
const SERVICE_PROVIDER_CONFIG = { "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"], "documentationUri": "http://example.com/help/scim.html", "patch": { "supported": true }, "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 }, "filter": { "supported": true, "maxResults": 100 }, "changePassword": { "supported": false }, "sort": { "supported": false }, "etag": { "supported": false }, "authenticationSchemes": [ { "name": "OAuth Bearer Token", "description": "Authentication scheme using the OAuth Bearer Token standard.", "specUri": "http://www.rfc-editor.org/info/rfc6750", "type": "oauthbearertoken", "primary": true } ], "meta": { "location": "/scim/v2/ServiceProviderConfig", "resourceType": "ServiceProviderConfig" } };
const USER_RESOURCE_TYPE = { "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User", "endpoint": "/scim/v2/Users", "description": "User Account", "schema": "urn:ietf:params:scim:schemas:core:2.0:User", "meta": { "location": "/scim/v2/ResourceTypes/User", "resourceType": "ResourceType" } };
const GROUP_RESOURCE_TYPE = { "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "Group", "name": "Group", "endpoint": "/scim/v2/Groups", "description": "Group", "schema": "urn:ietf:params:scim:schemas:core:2.0:Group", "meta": { "location": "/scim/v2/ResourceTypes/Group", "resourceType": "ResourceType" } };

const globalRequestLogger = (req, res, next) => {
    console.log('\n--- GLOBAL LOGGER: INCOMING REQUEST ---');
    console.log(`Timestamp: ${new Date().toISOString()}`);
    console.log(`Method: ${req.method}`);
    console.log(`Path: ${req.originalUrl}`);
    console.log('Headers:', JSON.stringify(req.headers, null, 2));

    if (req.body && Object.keys(req.body).length > 0) {
        console.log('Body:', JSON.stringify(req.body, null, 2));
    } else {
        console.log('Body: [Empty]');
    }
    console.log('-------------------------------------\n');
    next();
};


async function startServer() {
  try {
    // 1. DB Init
    await pool.query(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, userName TEXT UNIQUE, active BOOLEAN, scim_data JSONB)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS groups (id TEXT PRIMARY KEY, displayName TEXT UNIQUE, scim_data JSONB)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS group_members (group_id TEXT REFERENCES groups(id) ON DELETE CASCADE, user_id TEXT REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY (group_id, user_id))`);
    console.log("Database schema initialized successfully.");

    // 2. Configure Middleware
    app.set('trust proxy', 1);
    app.disable('x-frame-options');
    app.use(morgan('dev'));
    app.use(express.json({ type: ['application/json', 'application/scim+json'] }));
    app.use(express.urlencoded({ extended: true }));
    app.use(globalRequestLogger);

    app.set('view engine', 'ejs');
    app.set('views', path.join(__dirname, 'views'));
    app.use(session({
      secret: APP_SECRET, resave: false, saveUninitialized: true,
      cookie: { secure: true, httpOnly: true, sameSite: 'none' }
    }));

    // 3. OIDC and OAuth 2.0 Endpoints
    const oidc = new ExpressOIDC({
      issuer: `${OKTA_ORG_URL}/oauth2/default`, client_id: OKTA_CLIENT_ID_UI, client_secret: OKTA_CLIENT_SECRET_UI,
      appBaseUrl: process.env.BASE_URL, scope: 'openid profile',
      routes: { login: { path: '/login' }, callback: { path: '/authorization-code/callback', afterCallback: '/' } }
    });
    app.use(oidc.router);

    app.get('/authorize', (req, res) => {
        const { client_id, redirect_uri, state } = req.query;
        if (client_id !== OAUTH_CLIENT_ID) { return res.status(400).send("Invalid client_id"); }
        res.render('consent', { client_id, redirect_uri, state });
    });
    app.post('/authorize/grant', (req, res) => {
        const { client_id, redirect_uri, state } = req.body;
        const code = `code-${crypto.randomBytes(16).toString('hex')}`;
        authCodes.set(code, { clientId: client_id, expires: Date.now() + 60000 });
        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set('code', code);
        if (state) { redirectUrl.searchParams.set('state', state); }
        res.redirect(redirectUrl.href);
    });
    app.get('/token', (req, res) => {
        res.status(200).json({ message: "Token endpoint is reachable. Please use POST for actual token exchange." });
    });
    app.post('/token', (req, res) => {
        const { grant_type, code, client_id, client_secret } = req.body;
        if (grant_type !== 'authorization_code') { return res.status(400).json({ error: 'unsupported_grant_type' }); }
        if (client_id !== OAUTH_CLIENT_ID || client_secret !== OAUTH_CLIENT_SECRET) {
            return res.status(401).json({ error: 'invalid_client' });
        }
        const storedCode = authCodes.get(code);
        if (!storedCode || storedCode.expires < Date.now() || storedCode.clientId !== client_id) { return res.status(400).json({ error: 'invalid_grant' }); }
        authCodes.delete(code);
        res.status(200).json({ access_token: SCIM_ACCESS_TOKEN, token_type: 'Bearer', expires_in: 3600 });
    });

    // 4. SCIM Router
    const scimAuth = (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader || authHeader !== `Bearer ${SCIM_ACCESS_TOKEN}`) {
            return res.status(401).json({ detail: "Unauthorized - Invalid Access Token" });
        }
        next();
    };
    const scimRouter = express.Router();
    scimRouter.use(scimAuth);
    scimRouter.use('/users', usersRouter);
    scimRouter.use('/groups', groupsRouter);
    scimRouter.get('/ServiceProviderConfig', (req, res) => res.json(SERVICE_PROVIDER_CONFIG));
    scimRouter.get('/ResourceTypes', (req, res) => res.json({ Resources: [USER_RESOURCE_TYPE, GROUP_RESOURCE_TYPE] }));
    scimRouter.get('/Schemas', (req, res) => res.json({ Resources: SCHEMAS }));
    app.use('/scim/v2', scimRouter);

    // 5. UI Routes
    app.get('/', (req, res) => {
      if (req.userContext) { res.redirect('/ui/users'); }
      else { res.redirect('/login'); }
    });
    app.get('/login', (req, res) => res.render('login', { oktaOrgUrl: OKTA_ORG_URL, oktaClientId: OKTA_CLIENT_ID_UI }));
    app.get('/ui/users', oidc.ensureAuthenticated(), async (req, res) => {
        try {
            const { rows } = await pool.query(`SELECT scim_data FROM users ORDER BY userName`);
            const users = rows.map(row => row.scim_data);
            res.render('users', { users: users, user: req.userContext.userinfo });
        } catch (err) { res.status(500).send("Error retrieving users."); }
    });
    app.get('/ui/groups', oidc.ensureAuthenticated(), async (req, res) => {
        try {
            const query = `
                SELECT g.id, g.displayName AS "displayName", COALESCE(json_agg(json_build_object('value', u.id, 'display', u.userName)) FILTER (WHERE u.id IS NOT NULL), '[]') as members
                FROM groups g
                LEFT JOIN group_members gm ON g.id = gm.group_id
                LEFT JOIN users u ON gm.user_id = u.id
                GROUP BY g.id, g.displayName ORDER BY g.displayName;`;
            const { rows } = await pool.query(query);
            res.render('groups', { groups: rows, user: req.userContext.userinfo });
        } catch (err) {
            console.error("Error fetching groups for UI:", err);
            res.status(500).send("Error retrieving groups.");
        }
    });

    // 6. Start Listening
    app.listen(PORT, () => {
        console.log(`Server is running and ready on port ${PORT}`);
    });

  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
}

// Start the server
startServer();