const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const User = require("../models/User");

// Check if Google OAuth credentials are available
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/api/auth/google/callback",
        passReqToCallback: true,
        state: true,
      },
      async (req, accessToken, refreshToken, profile, done) => {
        try {
          // Validate redirect URI (prevent open redirect attacks)
          // Validate OAuth state parameter (CSRF protection)
          if (!req.query.state || req.query.state !== req.session?.oauthState) {
            return done(new Error("Invalid OAuth state parameter"), null);
          }

          // Sanitize and check email
          const emailObj = Array.isArray(profile.emails) && profile.emails[0] ? profile.emails[0] : null;
          const email = emailObj && emailObj.value ? emailObj.value : null;
          const emailVerified = emailObj && (emailObj.verified === true || emailObj.verified === 'true');
          if (!email || !emailVerified) {
            return done(new Error("Google account email not verified or missing."), null);
          }

          // Check if user already exists with this Google ID
          let user = await User.findOne({ googleId: profile.id });
          if (user) {
            return done(null, user);
          }

          // Check if user exists with the same email but different login method
          user = await User.findOne({ email });
          if (user) {
            // Link Google account to existing user
            user.googleId = profile.id;
            await user.save();
            return done(null, user);
          }

          // Create new user
          const newUser = new User({
            googleId: profile.id,
            userName: profile.displayName || (email ? email.split('@')[0] : `user_${profile.id}`),
            email,
            role: "user",
          });

          await newUser.save();
          return done(null, newUser);
        } catch (error) {
          console.error("Google OAuth Error:", error);
          return done(error, null);
        }
      }
    )
  );
  
  console.log("Google OAuth strategy configured successfully");
} else {
  console.warn("Google OAuth credentials not found. Google Sign-In will be disabled.");
}

// Check if Facebook OAuth credentials are available
if (process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET) {
  passport.use(
    new FacebookStrategy(
      {
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "/api/auth/facebook/callback",
        profileFields: ['id', 'emails', 'name', 'displayName'],
        passReqToCallback: true,
        state: true
      },
      async (req, accessToken, refreshToken, profile, done) => {
        try {
          // Validate redirect URI (prevent open redirect attacks)
          // Validate OAuth state parameter (CSRF protection)
          if (!req.query.state || req.query.state !== req.session?.oauthState) {
            return done(new Error("Invalid OAuth state parameter"), null);
          }

          // Facebook may not always return email, so handle that case
          const emailObj = Array.isArray(profile.emails) && profile.emails[0] ? profile.emails[0] : null;
          const email = emailObj && emailObj.value ? emailObj.value : null;
          // Facebook does not always provide email verification, so just check presence
          if (!email) {
            return done(new Error("Facebook account email missing."), null);
          }

          // Check if user already exists with this Facebook ID
          let user = await User.findOne({ facebookId: profile.id });
          if (user) {
            return done(null, user);
          }

          // Check if user exists with the same email but different login method
          user = await User.findOne({ email });
          if (user) {
            // Link Facebook account to existing user
            user.facebookId = profile.id;
            await user.save();
            return done(null, user);
          }

          // Generate a username if displayName is not available
          const userName = profile.displayName || (email ? email.split('@')[0] : `user_${profile.id}`);

          // Create new user
          const newUser = new User({
            facebookId: profile.id,
            userName: userName,
            email: email || `${profile.id}@facebook.com`, // Fallback email
            role: "user",
          });

          await newUser.save();
          return done(null, newUser);
        } catch (error) {
          console.error("Facebook OAuth Error:", error);
          return done(error, null);
        }
      }
    )
  );
  
  console.log("Facebook OAuth strategy configured successfully");
} else {
  console.warn("Facebook OAuth credentials not found. Facebook Sign-In will be disabled.");
}

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

module.exports = passport;