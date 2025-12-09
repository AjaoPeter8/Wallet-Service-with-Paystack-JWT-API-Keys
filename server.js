import express from 'express';
import session from 'express-session';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import './passport.js';

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret';
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET || 'your-paystack-secret';
const SESSION_SECRET = process.env.SESSION_SECRET || 'your-session-secret';

// MySQL connection
// MySQL connection
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'wallet_service',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test database connection
db.getConnection()
    .then(connection => {
        console.log('✅ Database connected successfully');
        connection.release();
    })
    .catch(error => {
        console.error('❌ Database connection failed:', error.message);
    });


// Helper functions
const generateWalletNumber = () => Math.floor(1000000000000 + Math.random() * 9000000000000).toString();
const generateApiKey = () => 'sk_live_' + crypto.randomBytes(32).toString('hex');
const parseExpiry = (expiry) => {
    const now = new Date();
    switch(expiry) {
        case '1H': return new Date(now.getTime() + 60 * 60 * 1000);
        case '1D': return new Date(now.getTime() + 24 * 60 * 60 * 1000);
        case '1M': return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
        case '1Y': return new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
        default: throw new Error('Invalid expiry format');
    }
};

// Authentication middleware
const authMiddleware = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    const apiKeyHeader = req.headers['x-api-key'];

    if (apiKeyHeader) {
        try {
            const [rows] = await db.execute(
                'SELECT * FROM api_keys WHERE revoked = FALSE AND expires_at > NOW()',
                []
            );
            
            let foundKey = null;
            for (const key of rows) {
                const isValid = await bcrypt.compare(apiKeyHeader, key.key_hash);
                if (isValid) {
                    foundKey = key;
                    break;
                }
            }

            if (!foundKey) {
                return res.status(401).json({ error: 'Invalid or expired API key' });
            }

            req.user = { id: foundKey.user_id };
            req.apiKey = { ...foundKey, permissions: JSON.parse(foundKey.permissions) };
            req.authType = 'service';
            return next();
        } catch (error) {
            return res.status(500).json({ error: 'Database error' });
        }
    }

    if (authHeader?.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
            req.authType = 'user';
            return next();
        } catch (error) {
            return res.status(401).json({ error: 'Invalid token' });
        }
    }

    return res.status(401).json({ error: 'No valid authentication provided' });
};

// Permission check middleware
const checkPermission = (permission) => (req, res, next) => {
    if (req.authType === 'user') return next();
    if (req.apiKey?.permissions?.includes(permission)) return next();
    return res.status(403).json({ error: 'Insufficient permissions' });
};

// Session setup
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

// Google OAuth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
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
            const walletId = crypto.randomUUID();
            await db.execute(
                'INSERT IGNORE INTO wallets (id, user_id, wallet_number) VALUES (?, ?, ?)',
                [walletId, user.id, generateWalletNumber()]
            );

            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
            res.json({ token, user });
        } catch (error) {
            res.status(500).json({ error: 'Database error' });
        }
    }
);

// API Key Management
app.post('/keys/create', authMiddleware, async (req, res) => {
    const { name, permissions, expiry } = req.body;

    if (!name || !permissions || !expiry) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
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
            [keyId, req.user.id, name, keyHash, JSON.stringify(permissions), expiresAt]
        );

        res.json({
            api_key: apiKey,
            expires_at: expiresAt.toISOString()
        });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/keys/rollover', authMiddleware, async (req, res) => {
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

// Wallet endpoints
app.post('/wallet/deposit', authMiddleware, checkPermission('deposit'), async (req, res) => {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
    }

    try {
        const reference = 'ref_' + crypto.randomBytes(16).toString('hex');
        const transactionId = crypto.randomUUID();

        await db.execute(
            'INSERT INTO transactions (id, reference, user_id, type, amount, status) VALUES (?, ?, ?, ?, ?, ?)',
            [transactionId, reference, req.user.id, 'deposit', amount, 'pending']
        );

        res.json({
            reference,
            authorization_url: `https://checkout.paystack.com/${reference}`
        });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/wallet/paystack/webhook', async (req, res) => {
    const signature = req.headers['x-paystack-signature'];
    const body = JSON.stringify(req.body);
    const hash = crypto.createHmac('sha512', PAYSTACK_SECRET).update(body).digest('hex');

    if (signature !== hash) {
        return res.status(400).json({ error: 'Invalid signature' });
    }

    const { event, data } = req.body;

    if (event === 'charge.success') {
        try {
            const connection = await db.getConnection();
            await connection.beginTransaction();

            const [transactions] = await connection.execute(
                'SELECT * FROM transactions WHERE reference = ? AND status = "pending"',
                [data.reference]
            );

            if (transactions.length > 0) {
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

app.get('/wallet/deposit/:reference/status', authMiddleware, async (req, res) => {
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

app.get('/wallet/balance', authMiddleware, checkPermission('read'), async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT balance FROM wallets WHERE user_id = ?',
            [req.user.id]
        );

        res.json({ balance: rows.length > 0 ? parseFloat(rows[0].balance) : 0 });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/wallet/transfer', authMiddleware, checkPermission('transfer'), async (req, res) => {
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
            return res.status(400).json({ error: 'Insufficient balance' });
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

        await connection.execute(
            'UPDATE wallets SET balance = balance - ? WHERE user_id = ?',
            [amount, req.user.id]
        );

        await connection.execute(
            'UPDATE wallets SET balance = balance + ? WHERE wallet_number = ?',
            [amount, wallet_number]
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

app.get('/wallet/transactions', authMiddleware, checkPermission('read'), async (req, res) => {
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

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
