import express from 'express';
import crypto from 'crypto';
import axios from 'axios';
import { authMiddleware, checkPermission } from '../middleware/auth.js';
import { db } from '../config/database.js';

const router = express.Router();
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET || 'your-paystack-secret';

/**
 * @swagger
 * /wallet/deposit:
 *   post:
 *     summary: Initialize a deposit transaction
 *     tags: [Wallet]
 *     security:
 *       - bearerAuth: []
 *       - apiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - amount
 *             properties:
 *               amount:
 *                 type: number
 *                 description: Amount to deposit
 *                 example: 1000
 *     responses:
 *       200:
 *         description: Deposit initialized successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 reference:
 *                   type: string
 *                 authorization_url:
 *                   type: string
 *       400:
 *         description: Invalid amount
 *       500:
 *         description: Payment initialization failed
 */
router.post('/deposit', authMiddleware, checkPermission('deposit'), async (req, res) => {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
    }

    try {
        const reference = 'ref_' + crypto.randomBytes(16).toString('hex');
        const transactionId = crypto.randomUUID();

        const paystackResponse = await axios.post(
            'https://api.paystack.co/transaction/initialize',
            {
                email: req.user.email,
                amount: amount,
                reference: reference,
            },
            {
                headers: {
                    Authorization: `Bearer ${process.env.PAYSTACK_SECRET}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        const authUrl = paystackResponse.data.data.authorization_url;

        await db.execute(
            'INSERT INTO transactions (id, reference, user_id, type, amount, status) VALUES (?, ?, ?, ?, ?, ?)',
            [transactionId, reference, req.user.id, 'deposit', amount, 'pending']
        );

        res.json({
            reference,
            authorization_url: authUrl
        });
    } catch (error) {
        res.status(500).json({ error: 'Payment initialization failed' });
    }
});

/**
 * @swagger
 * /wallet/paystack/webhook:
 *   post:
 *     summary: Paystack webhook for payment notifications
 *     tags: [Wallet]
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Webhook processed
 *       400:
 *         description: Invalid signature
 */
router.post('/paystack/webhook', async (req, res) => {
    const signature = req.headers['x-paystack-signature'];
    const body = JSON.stringify(req.body);
    const hash = crypto.createHmac('sha512', PAYSTACK_SECRET).update(body).digest('hex');
    
    if (signature !== hash) {
        return res.status(400).json({ error: 'Invalid signature' });
    }

    const { event, data } = req.body;
    if (event === 'charge.success') {
        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            // Use FOR UPDATE to lock the row and prevent race conditions
            const [transactions] = await connection.execute(
                'SELECT * FROM transactions WHERE reference = ? FOR UPDATE',
                [data.reference]
            );

            if (transactions.length > 0 && transactions[0].status === 'pending') {
                const transaction = transactions[0];

                await connection.execute(
                    'UPDATE transactions SET status = "success" WHERE id = ?',
                    [transaction.id]
                );

                await connection.execute(
                    'UPDATE wallets SET balance = balance + ? WHERE user_id = ?',
                    [transaction.amount, transaction.user_id]
                );
            }

            await connection.commit();
            connection.release();
        } catch (error) {
            await connection.rollback();
            connection.release();
        }
    }

    res.json({ status: true });
});

/**
 * @swagger
 * /wallet/deposit/{reference}/status:
 *   get:
 *     summary: Check deposit transaction status
 *     tags: [Wallet]
 *     security:
 *       - bearerAuth: []
 *       - apiKeyAuth: []
 *     parameters:
 *       - in: path
 *         name: reference
 *         required: true
 *         schema:
 *           type: string
 *         description: Transaction reference
 *     responses:
 *       200:
 *         description: Transaction status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 reference:
 *                   type: string
 *                 status:
 *                   type: string
 *                 amount:
 *                   type: number
 *       404:
 *         description: Transaction not found
 */
router.get('/deposit/:reference/status', authMiddleware, async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT * FROM transactions WHERE reference = ? AND user_id = ?',
            [req.params.reference, req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Transaction not found' });
        }

        const transaction = rows[0];
        res.json({
            reference: transaction.reference,
            status: transaction.status,
            amount: parseFloat(transaction.amount)
        });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});

/**
 * @swagger
 * /wallet/balance:
 *   get:
 *     summary: Get wallet balance
 *     tags: [Wallet]
 *     security:
 *       - bearerAuth: []
 *       - apiKeyAuth: []
 *     responses:
 *       200:
 *         description: Wallet balance
 *         content:
 *           application/json:
*             schema:
 *               type: object
 *               properties:
 *                 balance:
 *                   type: number
 *                 wallet_number:
 *                   type: string
 *       500:
 *         description: Database error
 */
router.get('/balance', authMiddleware, checkPermission('read'), async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT balance, wallet_number FROM wallets WHERE user_id = ?',
            [req.user.id]
        );

        res.json({ 
            balance: rows.length > 0 ? parseFloat(rows[0].balance) : 0,
            wallet_number: rows.length > 0 ? rows[0].wallet_number : null
        });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});

/**
 * @swagger
 * /wallet/transfer:
 *   post:
 *     summary: Transfer funds to another wallet
 *     tags: [Wallet]
 *     security:
 *       - bearerAuth: []
 *       - apiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - wallet_number
 *               - amount
 *             properties:
 *               wallet_number:
 *                 type: string
 *                 description: Recipient wallet number
 *               amount:
 *                 type: number
 *                 description: Amount to transfer
 *                 example: 500
 *     responses:
 *       200:
 *         description: Transfer completed
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 message:
 *                   type: string
 *       400:
 *         description: Invalid parameters or insufficient balance
 *       404:
 *         description: Recipient wallet not found
 */
router.post('/transfer', authMiddleware, checkPermission('transfer'), async (req, res) => {
    const { wallet_number, amount } = req.body;

    if (!wallet_number || !amount || amount <= 0) {
        return res.status(400).json({ error: 'Invalid parameters' });
    }

    try {
        const connection = await db.getConnection();
        await connection.beginTransaction();

        const [senderWallet] = await connection.execute(
            'SELECT * FROM wallets WHERE user_id = ? FOR UPDATE',
            [req.user.id]
        );

        if (senderWallet.length === 0 || parseFloat(senderWallet[0].balance) < amount) {
            await connection.rollback();
            connection.release();
            return res.status(200).json({ error: 'Insufficient balance' });
        }

        const [recipientWallet] = await connection.execute(
            'SELECT * FROM wallets WHERE wallet_number = ? FOR UPDATE',
            [wallet_number]
        );

        if (recipientWallet.length === 0) {
            await connection.rollback();
            connection.release();
            return res.status(404).json({ error: 'Recipient wallet not found' });
        }

        if (recipientWallet[0].user_id === req.user.id) {
            await connection.rollback();
            connection.release();
            return res.status(400).json({ error: 'Cannot transfer to own wallet' });
        }

        const senderBalance = parseFloat(senderWallet[0].balance) - amount;
        const recipientBalance = parseFloat(recipientWallet[0].balance) + amount;

        console.log('Sender Balance:', senderBalance);
        console.log('Recipient Balance:', recipientBalance);

        await connection.execute(
            'UPDATE wallets SET balance = ? WHERE user_id = ?',
            [senderBalance, req.user.id]
        );

        await connection.execute(
            'UPDATE wallets SET balance = ? WHERE wallet_number = ?',
            [recipientBalance, wallet_number]
        );

        const transferId = crypto.randomUUID();
        await connection.execute(
            'INSERT INTO transactions (id, reference, user_id, type, amount, status) VALUES (?, ?, ?, ?, ?, ?)',
            [crypto.randomUUID(), transferId + '_out', req.user.id, 'transfer', -amount, 'success']
        );

        await connection.execute(
            'INSERT INTO transactions (id, reference, user_id, type, amount, status) VALUES (?, ?, ?, ?, ?, ?)',
            [crypto.randomUUID(), transferId + '_in', recipientWallet[0].user_id, 'transfer', amount, 'success']
        );

        await connection.commit();
        connection.release();

        res.json({
            status: 'success',
            message: 'Transfer completed'
        });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});

/**
 * @swagger
 * /wallet/transactions:
 *   get:
 *     summary: Get transaction history
 *     tags: [Wallet]
 *     security:
 *       - bearerAuth: []
 *       - apiKeyAuth: []
 *     responses:
 *       200:
 *         description: List of transactions
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Transaction'
 *       500:
 *         description: Database error
 */
router.get('/transactions', authMiddleware, checkPermission('read'), async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT type, amount, status, created_at FROM transactions WHERE user_id = ? ORDER BY created_at DESC',
            [req.user.id]
        );

        const transactions = rows.map(t => ({
            type: t.type,
            amount: Math.abs(parseFloat(t.amount)),
            status: t.status,
            createdAt: t.created_at
        }));

        res.json(transactions);
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});

export default router;