const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  resetToken: {
    type: String
  },
    role: { 
    type: String, 
    enum: ["user", "admin"], 
    default: "user" // Everyone starts as a regular user
  },
  resetTokenExpiry: {
    type: Date
  }
},
 {
    timestamps: true, // ✅ THIS must be inside second argument
  }
);

module.exports = mongoose.model("User", UserSchema);
