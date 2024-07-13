import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";

// Web authentication strategy
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.CLIENT_ID,
            clientSecret: process.env.CLIENT_SECRET,
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
