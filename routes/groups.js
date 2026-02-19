// routes/groups.js (with PUT and PATCH support)

import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import pg from 'pg';

const router = Router();
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// GET /scim/v2/Groups - List Groups with Pagination (Unchanged)
router.get('/', async (req, res) => {
    try {
        const startIndex = parseInt(req.query.startIndex, 10) || 1;
        const count = parseInt(req.query.count, 10) || 100;
        const totalResultPromise = pool.query(`SELECT COUNT(*) AS total FROM groups`);
        const groupsPromise = pool.query(`SELECT scim_data FROM groups ORDER BY displayName LIMIT $1 OFFSET $2`, [count, startIndex - 1]);
        const [totalResult, groupsResult] = await Promise.all([totalResultPromise, groupsPromise]);
        const totalResults = parseInt(totalResult.rows[0].total, 10);
        const resources = groupsResult.rows.map(row => row.scim_data);
        res.json({
            schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            totalResults,
            itemsPerPage: resources.length,
            startIndex,
            Resources: resources
        });
    } catch (err) {
        console.error("Error in GET /Groups:", err);
        res.status(500).json({ detail: "Database query error" });
    }
});

// GET /scim/v2/Groups/{id} - Get a single Group with its members (Unchanged)
router.get('/:id', async (req, res) => {
    const groupId = req.params.id;
    try {
        const groupResult = await pool.query(`SELECT scim_data FROM groups WHERE id = $1`, [groupId]);
        if (groupResult.rows.length === 0) {
            return res.status(404).json({ detail: "Group not found" });
        }
        const group = groupResult.rows[0].scim_data;
        const membersResult = await pool.query(`SELECT u.scim_data FROM users u JOIN group_members gm ON u.id = gm.user_id WHERE gm.group_id = $1`,[groupId]);
        group.members = membersResult.rows.map(row => {
            const user = row.scim_data;
            return { value: user.id, display: user.userName };
        });
        res.status(200).json(group);
    } catch (err) {
        console.error(`Error in GET /Groups/${groupId}:`, err);
        res.status(500).json({ detail: "Database query error" });
    }
});

// POST /scim/v2/Groups - Create a new Group (Unchanged)
router.post('/', async (req, res) => {
    const { displayName } = req.body;
    if (!displayName) { return res.status(400).json({ detail: 'displayName is required' }); }
    const groupId = uuidv4();
    const newGroup = {
        id: groupId,
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        displayName,
        members: [],
        meta: { resourceType: "Group", created: new Date().toISOString(), lastModified: new Date().toISOString(), location: `/scim/v2/Groups/${groupId}` }
    };
    try {
        await pool.query(`INSERT INTO groups (id, displayName, scim_data) VALUES ($1, $2, $3)`, [groupId, displayName, newGroup]);
        res.status(201).json(newGroup);
    } catch (err) {
        console.error("Error in POST /Groups:", err);
        res.status(500).json({ detail: "Database error" });
    }
});

// ** NEW: Fully replace a Group and its members **
router.put('/:id', async (req, res) => {
    const groupId = req.params.id;
    const { displayName, members } = req.body;

    if (!displayName) {
        return res.status(400).json({ detail: 'displayName is required for PUT' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // Start transaction

        // 1. Update the group's core data
        const updatedGroupData = {
            id: groupId,
            displayName,
            schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            meta: { resourceType: "Group", lastModified: new Date().toISOString(), location: `/scim/v2/Groups/${groupId}` }
        };
        const groupUpdateResult = await client.query(
            `UPDATE groups SET displayName = $1, scim_data = $2 WHERE id = $3`,
            [displayName, updatedGroupData, groupId]
        );

        if (groupUpdateResult.rowCount === 0) {
            // If the group doesn't exist, you could choose to create it (upsert) or fail.
            // Failing is safer and more compliant with PUT semantics.
            throw new Error('Group not found');
        }

        // 2. Delete all existing members for this group
        await client.query(`DELETE FROM group_members WHERE group_id = $1`, [groupId]);

        // 3. Insert the new list of members, if any
        if (members && Array.isArray(members) && members.length > 0) {
            for (const member of members) {
                if (member.value) {
                    await client.query(
                        `INSERT INTO group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
                        [groupId, member.value]
                    );
                }
            }
        }
        
        await client.query('COMMIT'); // Commit transaction

        // 4. Fetch the final state of the group to return it
        const finalGroup = await getGroupWithMembers(groupId);
        res.status(200).json(finalGroup);

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(`Error in PUT /Groups/${groupId}:`, err);
        if (err.message === 'Group not found') {
            return res.status(404).json({ detail: 'Group not found' });
        }
        res.status(500).json({ detail: "Error processing PUT operation" });
    } finally {
        client.release();
    }
});


// PATCH /scim/v2/Groups/{id} - Partially update membership (Unchanged)
router.patch('/:id', async (req, res) => {
    const groupId = req.params.id;
    const { Operations } = req.body;
    if (!Operations || !Array.isArray(Operations)) {
        return res.status(400).json({ detail: "Invalid PATCH request" });
    }
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        for (const op of Operations) {
            if (op.op.toLowerCase() === 'add' && op.path === 'members') {
                const memberIds = op.value.map(v => v.value);
                for (const userId of memberIds) {
                    await client.query(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [groupId, userId]);
                }
            } else if (op.op.toLowerCase() === 'remove' && op.path && op.path.startsWith('members')) {
                const match = op.path.match(/\[value eq "(.+?)"\]/);
                if (match && match[1]) {
                    const userId = match[1];
                    await client.query(`DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, [groupId, userId]);
                }
            } else if (op.op.toLowerCase() === 'replace' && op.path === 'displayName') {
                await client.query(`UPDATE groups SET displayName = $1 WHERE id = $2`, [op.value, groupId]);
            }
        }
        await client.query('COMMIT');
        res.status(204).send();
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(`Error in PATCH /Groups/${groupId}:`, err);
        res.status(500).json({ detail: "Error processing PATCH operation" });
    } finally {
        client.release();
    }
});


// ** NEW: Helper function to get a group and its members, to avoid code duplication **
async function getGroupWithMembers(groupId) {
    const groupResult = await pool.query(`SELECT scim_data FROM groups WHERE id = $1`, [groupId]);
    if (groupResult.rows.length === 0) {
        throw new Error('Group not found');
    }
    const group = groupResult.rows[0].scim_data;

    const membersResult = await pool.query(
        `SELECT u.scim_data FROM users u JOIN group_members gm ON u.id = gm.user_id WHERE gm.group_id = $1`,
        [groupId]
    );

    group.members = membersResult.rows.map(row => {
        const user = row.scim_data;
        return { value: user.id, display: user.userName };
    });
    
    return group;
}

export default router;