import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import dotenv from 'dotenv';
dotenv.config();

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: '/auth/google/callback', // Must match one in Google Cloud Console
    },
    async (accessToken, refreshToken, profile, done) => {
      // Logic to find or create user in your database
      // based on profile information (profile.id, profile.displayName, profile.emails[0].value)
      // Call done(null, user) when complete
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  // Logic to find user by ID in your database
  // Call done(null, user) when complete
});