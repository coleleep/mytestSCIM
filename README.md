# mytestSCIM

A SCIM 2.0 server built with Node.js, Express, and PostgreSQL. Supports provisioning users and groups via SCIM, with a web UI to view provisioned data. Designed to be deployed on [Render](https://render.com) with a [Neon](https://neon.tech) database.

## What is SCIM?

SCIM (System for Cross-domain Identity Management) is a standard API protocol that identity providers like Okta use to automatically provision and deprovision users and groups in downstream applications. This server acts as the "app" side of that connection.

---

## Prerequisites

- A [Render](https://render.com) account (free tier works)
- A [Neon](https://neon.tech) account (free tier works)
- An Okta org (or another IdP that supports SCIM)

---

## Step 1: Set Up Your Neon Database

1. Log in to [neon.tech](https://neon.tech) and create a new project.
2. Once created, go to your project dashboard and find the **Connection string** under the **Connection Details** panel.
3. Copy the connection string — it looks like:
   ```
   postgresql://user:password@ep-xxx.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```
4. Save this — you'll use it as `DATABASE_URL` in the next step.

> The server automatically creates the required tables (`users`, `groups`, `group_members`) on startup. No manual migrations needed.

---

## Step 2: Deploy to Render

1. Fork or push this repo to GitHub.
2. Log in to [render.com](https://render.com) and click **New > Web Service**.
3. Connect your GitHub repo.
4. Configure the service:
   - **Runtime:** Node
   - **Build Command:** `npm install`
   - **Start Command:** `node server.js`
5. Under **Environment Variables**, add all the variables from the table below.
6. Click **Create Web Service**. Render will build and deploy automatically.

Once deployed, your service URL will look like `https://your-app-name.onrender.com`. This is your SCIM base URL.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | Neon PostgreSQL connection string |
| `APP_SECRET` | Yes | Random secret for session encryption (generate with `openssl rand -hex 32`) |
| `OKTA_ORG_URL` | Yes | Your Okta org URL, e.g. `https://dev-123456.okta.com` |
| `OKTA_CLIENT_ID_UI` | Yes | Client ID of the Okta OIDC app used for web UI login |
| `OKTA_CLIENT_SECRET_UI` | Yes | Client secret of the Okta OIDC app used for web UI login |
| `SCIM_ACCESS_TOKEN` | No | Static Bearer token for SCIM auth. Auto-generated on startup if not set — check logs for the value |
| `SCIM_BASIC_USER` | No | Username for HTTP Basic auth (required if using Basic auth) |
| `SCIM_BASIC_PASS` | No | Password for HTTP Basic auth (required if using Basic auth) |
| `OAUTH_CLIENT_ID` | No | Client ID for OAuth 2.0 / Client Credentials auth |
| `OAUTH_CLIENT_SECRET` | No | Client secret for OAuth 2.0 / Client Credentials auth |
| `PORT` | No | Port to listen on (Render sets this automatically) |

---

## Step 3: Configure SCIM in Your IdP

Point your identity provider at this server. Use your Render URL as the SCIM base URL:

```
https://your-app-name.onrender.com/scim/v2
```

### Authentication Options

This server supports four authentication methods. Use whichever your IdP supports.

#### 1. Bearer Token (recommended)
Set `SCIM_ACCESS_TOKEN` to a static token value. In your IdP, select **Bearer Token** and paste the value.

If you don't set `SCIM_ACCESS_TOKEN`, a token is auto-generated on each startup and printed to the logs — not suitable for production.

#### 2. HTTP Basic Auth
Set both `SCIM_BASIC_USER` and `SCIM_BASIC_PASS`. In your IdP, select **Basic Auth** and enter those credentials.

#### 3. OAuth 2.0 Authorization Code
Set `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET`. The authorization endpoint is:
```
https://your-app-name.onrender.com/authorize
```
The token endpoint is:
```
https://your-app-name.onrender.com/token
```

#### 4. Client Credentials
Same `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` as above. Use the token endpoint directly:
```
POST https://your-app-name.onrender.com/token
grant_type=client_credentials&client_id=...&client_secret=...
```

---

## SCIM Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/scim/v2/Users` | List users |
| `POST` | `/scim/v2/Users` | Create user |
| `GET` | `/scim/v2/Users/:id` | Get user |
| `PUT` | `/scim/v2/Users/:id` | Replace user |
| `PATCH` | `/scim/v2/Users/:id` | Update user (activate/deactivate) |
| `DELETE` | `/scim/v2/Users/:id` | Delete user |
| `GET` | `/scim/v2/Groups` | List groups |
| `POST` | `/scim/v2/Groups` | Create group |
| `GET` | `/scim/v2/Groups/:id` | Get group |
| `PUT` | `/scim/v2/Groups/:id` | Replace group |
| `PATCH` | `/scim/v2/Groups/:id` | Update group members |
| `DELETE` | `/scim/v2/Groups/:id` | Delete group |
| `GET` | `/scim/v2/ServiceProviderConfig` | SCIM capabilities |
| `GET` | `/scim/v2/Schemas` | Schema definitions |
| `GET` | `/scim/v2/ResourceTypes` | Resource type definitions |

---

## Web UI

The server includes a simple UI to view provisioned users and groups. It's protected by Okta OIDC login.

1. Set up an **OIDC Web Application** in Okta.
2. Add your Render URL as an allowed **Sign-in redirect URI**:
   ```
   https://your-app-name.onrender.com/authorization-code/callback
   ```
3. Set `OKTA_ORG_URL`, `OKTA_CLIENT_ID_UI`, and `OKTA_CLIENT_SECRET_UI` in your Render environment variables.
4. Visit `https://your-app-name.onrender.com/ui/users` to see provisioned users.

---

## Local Development

```bash
npm install
```

Create a `.env` file with the variables listed above, then:

```bash
node server.js
```

Server runs on `http://localhost:3000` by default.
