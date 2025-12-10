import express from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { authMiddleware } from '../middleware/auth.js';
import { db } from '../config/database.js';
import { generateApiKey, parseExpiry } from '../utils/helpers.js';

const router = express.Router();

/**
 * @swagger
 * /keys/create:
 *   post:
 *     summary: Create a new API key
 *     tags: [API Keys]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - expiry
 *             properties:
 *               name:
 *                 type: string
 *                 description: API key name
 *               permissions:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: List of permissions (read, deposit, transfer)
 *                 example: ["read", "deposit"]
 *               expiry:
 *                 type: string
 *                 description: Expiry duration (e.g., 30d, 1y)
 *                 example: "30d"
 *     responses:
 *       200:
 *         description: API key created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 api_key:
 *                   type: string
 *                 expires_at:
 *                   type: string
 *                   format: date-time
 *       400:
 *         description: Invalid request or limit exceeded
 *       403:
 *         description: Only users can create API keys
 */
router.post('/create', authMiddleware, async (req, res) => {
    const { name, permissions, expiry } = req.body;

    if (req.authType !== 'user') {
        return res.status(403).json({ error: 'Only users can create API keys' });
    }

    if (!name || !expiry) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const validPermissions = permissions && Array.isArray(permissions) ? permissions : [];

    try {
        // Check if name already exists for this user
        const [nameCheck] = await db.execute(
            'SELECT COUNT(*) as count FROM api_keys WHERE user_id = ? AND name = ? AND revoked = FALSE',
            [req.user.id, name]
        );

        if (nameCheck[0].count > 0) {
            return res.status(400).json({ error: 'API key name already exists' });
        }

        // Check active keys limit
        const [rows] = await db.execute(
            'SELECT COUNT(*) as count FROM api_keys WHERE user_id = ? AND revoked = FALSE AND expires_at > NOW()',
            [req.user.id]
        );

        if (rows[0].count >= 5) {
            return res.status(400).json({ error: 'Maximum 5 active API keys allowed' });
        }

        const expiresAt = parseExpiry(expiry);
        const keyId = crypto.randomUUID();
        const apiKey = generateApiKey();
        const keyHash = await bcrypt.hash(apiKey, 10);

        await db.execute(
            'INSERT INTO api_keys (id, user_id, name, key_hash, permissions, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
            [keyId, req.user.id, name, keyHash, JSON.stringify(validPermissions), expiresAt]
        );

        res.json({
            api_key: apiKey,
            expires_at: expiresAt.toISOString()
        });
    } catch (error) {
        res.status(500).json({ error: 'Database error', details: error.message });
    }
});

/**
 * @swagger
 * /keys/rollover:
 *   post:
 *     summary: Rollover an expired API key
 *     tags: [API Keys]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - expired_key_id
 *               - expiry
 *             properties:
 *               expired_key_id:
 *                 type: string
 *                 description: ID of the expired API key
 *               expiry:
 *                 type: string
 *                 description: New expiry duration
 *                 example: "30d"
 *     responses:
 *       200:
 *         description: API key rolled over successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 api_key:
 *                   type: string
 *                 expires_at:
 *                   type: string
 *                   format: date-time
 *       404:
 *         description: Expired key not found
 */
router.post('/rollover', authMiddleware, async (req, res) => {
    const { expired_key_id, expiry } = req.body;

    try {
        const [rows] = await db.execute(
            'SELECT * FROM api_keys WHERE id = ? AND user_id = ? AND expires_at <= NOW()',
            [expired_key_id, req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Expired key not found' });
        }

        const oldKey = rows[0];
        const expiresAt = parseExpiry(expiry);
        const keyId = crypto.randomUUID();
        const apiKey = generateApiKey();
        const keyHash = await bcrypt.hash(apiKey, 10);

        await db.execute(
            'INSERT INTO api_keys (id, user_id, name, key_hash, permissions, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
            [keyId, req.user.id, oldKey.name, keyHash, oldKey.permissions, expiresAt]
        );

        res.json({
            api_key: apiKey,
            expires_at: expiresAt.toISOString()
        });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});
/**
 * @swagger
 * /keys/{name}:
 *   delete:
 *     summary: Revoke an API key
 *     tags: [API Keys]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: name
 *         required: true
 *         schema:
 *           type: string
 *         description: API key name
 *     responses:
 *       200:
 *         description: API key revoked successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *       403:
 *         description: Only users can revoke API keys
 *       404:
 *         description: API key not found
 */
router.delete('/:name', authMiddleware, async (req, res) => {
    if (req.authType !== 'user') {
        return res.status(403).json({ error: 'Only users can revoke API keys' });
    }

    try {
        const [rows] = await db.execute(
            'SELECT * FROM api_keys WHERE name = ? AND user_id = ? AND revoked = FALSE',
            [req.params.name, req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'API key not found' });
        }

        await db.execute(
            'UPDATE api_keys SET revoked = TRUE WHERE name = ? AND user_id = ?',
            [req.params.name, req.user.id]
        );

        res.json({ message: 'API key revoked successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});


export default router;