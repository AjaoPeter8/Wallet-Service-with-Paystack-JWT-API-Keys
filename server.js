import express from 'express';
import session from 'express-session';
import passport from 'passport';
import dotenv from 'dotenv';
import swaggerUi from 'swagger-ui-express';

import authRoutes from './src/routes/auth.js';
import walletRoutes from './src/routes/wallet.js';
import apiKeyRoutes from './src/routes/apiKeys.js';
import './src/config/passport.js';
import { swaggerSpec } from './src/config/swagger.js';

dotenv.config();

const app = express();

// CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, x-api-key');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const SESSION_SECRET = process.env.SESSION_SECRET || 'your-session-secret';
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

// Swagger Documentation
app.get('/', (req, res) => res.redirect('/api-docs'));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Routes
app.use('/auth', authRoutes);
app.use('/wallet', walletRoutes);
app.use('/keys', apiKeyRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});