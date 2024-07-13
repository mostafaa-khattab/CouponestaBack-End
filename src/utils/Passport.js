import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";

// Web authentication strategy
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.CLIENT_ID || "788276623641-3uglucqsge7hknpqmupo67ehpfvq70cg.apps.googleusercontent.com",
            clientSecret: process.env.CLIENT_SECRET || "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",
            callbackURL: 'https://saraha-seej.onrender.com/auth/google/callback',
            passReqToCallback: true,
            scope: ['profile', 'email']
        },
        (req, accessToken, refreshToken, profile, done) => {

            // Web authentication logic
            return done(null, profile);
        }
    )
);

passport.serializeUser((user, done) => {
    done(null, user);
})

passport.deserializeUser((user, done) => {
    done(null, user);
})

export default passport
