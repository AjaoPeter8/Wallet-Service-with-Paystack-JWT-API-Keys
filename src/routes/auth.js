import express from 'express';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { db } from '../config/database.js';
import { generateWalletNumber } from '../utils/helpers.js';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret';

/**
 * @swagger
 * /auth/google:
 *   get:
 *     summary: Initiate Google OAuth authentication
 *     tags: [Authentication]
 *     security: []
 *     responses:
 *       302:
 *         description: Redirects to Google OAuth consent screen
 */
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

/**
 * @swagger
 * /auth/google/callback:
 *   get:
 *     summary: Google OAuth callback endpoint
 *     tags: [Authentication]
 *     security: []
 *     responses:
 *       200:
 *         description: Authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: JWT token
 *                 user:
 *                   $ref: '#/components/schemas/User'
 *       500:
 *         description: Database error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get('/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    async (req, res) => {
        try {
            const user = {
                id: req.user.id,
                email: req.user.emails[0].value,
                name: req.user.displayName
            };

            // Insert or update user
            await db.execute(
                'INSERT INTO users (id, email, name) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE name = VALUES(name)',
                [user.id, user.email, user.name]
            );

            // Create wallet if doesn't exist
            const [rows] = await db.execute(
                'SELECT * FROM wallets WHERE user_id = ?', [user.id]);
            
            if (rows.length < 1) {
                const walletId = crypto.randomUUID();
                await db.execute(
                    'INSERT INTO wallets (id, user_id, wallet_number) VALUES (?, ?, ?)',
                    [walletId, user.id, generateWalletNumber()]
                );
            }

            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
            res.json({ token, user });
        } catch (error) {
            res.status(500).json({ error: 'Database error', details: error.message });
        }
    }
);

export default router;