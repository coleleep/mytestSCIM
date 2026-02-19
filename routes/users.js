// routes/users.js (with the missing export statement)

import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import pg from 'pg';

const router = Router();
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// GET /scim/v2/Users - with Pagination and Filtering
router.get('/', async (req, res) => {
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
        const usersPromise = pool.query(
            `SELECT scim_data FROM users ${filterClause} ORDER BY userName LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`,
            [...queryParams, count, startIndex - 1]
        );

        const [totalResult, usersResult] = await Promise.all([totalResultPromise, usersPromise]);

        const totalResults = parseInt(totalResult.rows[0].total, 10);
        const resources = usersResult.rows.map(row => row.scim_data);

        res.json({
            schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            totalResults,
            itemsPerPage: resources.length,
            startIndex,
            Resources: resources
        });
    } catch (err) {
        console.error("Error in GET /Users:", err);
        res.status(500).json({ detail: "Database query error" });
    }
});

// GET /scim/v2/Users/{id}
router.get('/:id', async (req, res) => {
    try {
        const { rows } = await pool.query(`SELECT scim_data FROM users WHERE id = $1`, [req.params.id]);
        if (rows.length === 0) { return res.status(404).json({ detail: "User not found" }); }
        res.status(200).json(rows[0].scim_data);
    } catch (err) { res.status(500).json({ detail: "Database query error" }); }
});

// POST /scim/v2/Users
router.post('/', async (req, res) => {
    const scimUser = req.body; 
    if (!scimUser || !scimUser.userName) { return res.status(400).json({ detail: 'userName is required' }); }
    const userId = uuidv4();
    const newUser = { id: userId, schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: scimUser.userName, name: scimUser.name || {}, emails: scimUser.emails || [], active: scimUser.active !== undefined ? scimUser.active : true, meta: { resourceType: "User", created: new Date().toISOString(), lastModified: new Date().toISOString(), location: `/scim/v2/Users/${userId}` } };
    try {
        await pool.query(`INSERT INTO users (id, userName, active, scim_data) VALUES ($1, $2, $3, $4)`, [newUser.id, newUser.userName, newUser.active, newUser]);
        res.status(201).json(newUser);
    } catch (err) {
        if (err.code === '23505') { return res.status(409).json({ detail: 'userName must be unique.' }); }
        res.status(500).json({ detail: "Database insert error" });
    }
});

// PUT /scim/v2/Users/{id}
router.put('/:id', async (req, res) => {
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
        await pool.query(`UPDATE users SET userName = $1, active = $2, scim_data = $3 WHERE id = $4`, [updatedUser.userName, updatedUser.active, updatedUser, userId]);
        res.status(200).json(updatedUser);
    } catch (err) {
        if (err.code === '23505') { return res.status(409).json({ detail: 'userName must be unique.' }); }
        res.status(500).json({ detail: "Database error on update" });
    }
});

// PATCH /scim/v2/Users/{id}
router.patch('/:id', async (req, res) => {
    const userId = req.params.id;
    const { Operations } = req.body;
    if (!Operations) { return res.status(400).json({ detail: "PATCH request must contain 'Operations'" }); }
    const activeOp = Operations.find(op => op.op.toLowerCase() === 'replace' && op.path === 'active');
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

// DELETE /scim/v2/Users/{id}
router.delete('/:id', async (req, res) => {
    try {
        const result = await pool.query(`DELETE FROM users WHERE id = $1`, [req.params.id]);
        if (result.rowCount === 0) { return res.status(404).json({ detail: "User not found" }); }
        res.status(204).send();
    } catch (err) { res.status(500).json({ detail: "Database error" }); }
});

// ** THIS IS THE FIX: Export the router object as the default for this module **
export default router;

