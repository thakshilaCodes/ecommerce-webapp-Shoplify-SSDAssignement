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
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          console.log("Google OAuth Profile:", profile);

          // Check if user already exists with this Google ID
          let user = await User.findOne({ googleId: profile.id });

          if (user) {
            return done(null, user);
          }

          // Check if user exists with the same email but different login method
          user = await User.findOne({ email: profile.emails[0].value });

          if (user) {
            // Link Google account to existing user
            user.googleId = profile.id;
            await user.save();
            return done(null, user);
          }

          // Create new user
          const newUser = new User({
            googleId: profile.id,
            userName: profile.displayName,
            email: profile.emails[0].value,
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
        profileFields: ['id', 'emails', 'name', 'displayName']
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          console.log("Facebook OAuth Profile:", profile);

          // Check if user already exists with this Facebook ID
          let user = await User.findOne({ facebookId: profile.id });

          if (user) {
            return done(null, user);
          }

          // Facebook may not always return email, so handle that case
          const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
          
          if (email) {
            // Check if user exists with the same email but different login method
            user = await User.findOne({ email: email });

            if (user) {
              // Link Facebook account to existing user
              user.facebookId = profile.id;
              await user.save();
              return done(null, user);
            }
          }

          // Generate a username if displayName is not available
          const userName = profile.displayName || `user_${profile.id}`;
          
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