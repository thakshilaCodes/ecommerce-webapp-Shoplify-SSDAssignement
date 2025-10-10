const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  userName: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    // Make password optional for OAuth users
    required: function() {
      return !this.googleId && !this.facebookId; // Required only if not using OAuth
    }
  },
  role: {
    type: String,
    default: "user",
  },
  googleId: {
    type: String,
    sparse: true,
  },
  facebookId: {
    type: String,
    sparse: true,
  },
  profilePicture: {
    type: String,
    default: ""
  }
}, {
  timestamps: true
});

// Compound index to ensure email uniqueness
UserSchema.index({ email: 1 }, { unique: true });

const User = mongoose.model("User", UserSchema);
module.exports = User;