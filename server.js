import express from 'express';
import session from 'express-session';
import passport from 'passport';
import dotenv from 'dotenv';

import authRoutes from './src/routes/auth.js';
import walletRoutes from './src/routes/wallet.js';
import apiKeyRoutes from './src/routes/apiKeys.js';
import './src/config/passport.js';

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const SESSION_SECRET = process.env.SESSION_SECRET || 'your-session-secret';
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use('/auth', authRoutes);
app.use('/wallet', walletRoutes);
app.use('/keys', apiKeyRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});