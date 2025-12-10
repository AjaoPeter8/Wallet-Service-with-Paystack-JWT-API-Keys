import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { db } from '../config/database.js';

const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret';

export const authMiddleware = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    const apiKeyHeader = req.headers['x-api-key'];

    if (apiKeyHeader) {
        try {
            const [rows] = await db.execute(
                'SELECT * FROM api_keys WHERE revoked = FALSE AND expires_at > NOW()'
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

export const checkPermission = (permission) => (req, res, next) => {
    if (req.authType === 'user') return next();
    if (req.apiKey?.permissions?.includes(permission)) return next();
    return res.status(403).json({ error: 'Insufficient permissions' });
};