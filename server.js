// server.js (with secure session cookie configuration)

import express from 'express';
import pg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';
import morgan from 'morgan';
import session from 'express-session';
import OktaOidc from '@okta/oidc-middleware';
const { ExpressOIDC } = OktaOidc;

import usersRouter from './routes/users.js';
import groupsRouter from './routes/groups.js';

// --- Configuration (No changes) ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const OKTA_ORG_URL = process.env.OKTA_ORG_URL || 'https://YOUR_OKTA_DOMAIN';
const OKTA_CLIENT_ID_UI = process.env.OKTA_CLIENT_ID_UI || '{YourOktaUI_ClientID}';
const OKTA_CLIENT_SECRET_UI = process.env.OKTA_CLIENT_SECRET_UI || '{YourOktaUI_ClientSecret}';
const APP_SECRET = process.env.APP_SECRET || 'a-long-random-string-you-should-change';
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || OKTA_CLIENT_ID_UI;
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || OKTA_CLIENT_SECRET_UI;
const SCIM_ACCESS_TOKEN = process.env.SCIM_ACCESS_TOKEN || `tok-${crypto.randomBytes(24).toString('hex')}`;
//... (and so on, the rest of the config is unchanged)

// --- Main Server Function ---
async function startServer() {
  try {
    // DB Init (No changes)
    await pool.query(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, userName TEXT UNIQUE, active BOOLEAN, scim_data JSONB)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS groups (id TEXT PRIMARY KEY, displayName TEXT UNIQUE, scim_data JSONB)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS group_members (group_id TEXT REFERENCES groups(id) ON DELETE CASCADE, user_id TEXT REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY (group_id, user_id))`);
    console.log("Database schema initialized successfully.");

    const app = express();
    const PORT = process.env.PORT || 3000;

    // --- UPDATED: Secure Session Configuration ---
    // This is necessary for the OIDC flow to work behind a proxy like Render's.
    app.set('trust proxy', 1); // Trust the first proxy
    app.use(session({
        secret: APP_SECRET,
        resave: false,
        saveUninitialized: false, // Set to false for OIDC
        cookie: {
            secure: true, // Requires HTTPS
            httpOnly: true,
            sameSite: 'none' // Allow cookie to be sent in cross-site requests
        }
    }));
    
    // --- Rest of Middleware and Router Setup (No changes) ---
    app.use(morgan('dev'));
    app.use(express.json({ type: ['application/json', 'application/scim+json'] }));
    app.set('view engine', 'ejs');
    app.set('views', path.join(__dirname, 'views'));

    const oidc = new ExpressOIDC({
      issuer: `${OKTA_ORG_URL}/oauth2/default`,
      client_id: OKTA_CLIENT_ID_UI,
      client_secret: OKTA_CLIENT_SECRET_UI,
      appBaseUrl: process.env.BASE_URL || `http://localhost:${PORT}`,
      scope: 'openid profile',
      routes: {
          login: { path: '/login' },
          callback: {
              path: '/authorization-code/callback',
              afterCallback: '/' // Redirect to home after successful login
          }
      }
    });
    app.use(oidc.router);
    
    // ... (the rest of your server.js file is unchanged)
    const scimAuth = (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader || authHeader !== `Bearer ${API_TOKEN}`) { return res.status(401).json({ detail: "Unauthorized" }); }
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

    app.listen(PORT, () => {
        console.log(`Server is running and ready on port ${PORT}`);
    });

  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
}

startServer();
