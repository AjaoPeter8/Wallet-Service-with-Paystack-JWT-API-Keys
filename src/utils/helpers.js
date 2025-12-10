import crypto from 'crypto';

export const generateWalletNumber = () => 
    Math.floor(1000000000000 + Math.random() * 9000000000000).toString();

export const generateApiKey = () => 
    'sk_live_' + crypto.randomBytes(32).toString('hex');

export const parseExpiry = (expiry) => {
    const now = new Date();
    switch(expiry) {
        case '1H': return new Date(now.getTime() + 60 * 60 * 1000);
        case '1D': return new Date(now.getTime() + 24 * 60 * 60 * 1000);
        case '1M': return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
        case '1Y': return new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
        default: throw new Error('Invalid expiry format');
    }
};