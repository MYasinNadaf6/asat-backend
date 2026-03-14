const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");

/* =========================
   REGISTER
========================= */
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const userExists = await User.findOne({ email });
    if (userExists)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
    });

    await user.save();
    res.json({ message: "Account created successfully" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   LOGIN
========================= */
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      token,
      user: { name: user.name, email: user.email },
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   FORGOT PASSWORD (EMAIL)
========================= */
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    console.log("FORGOT PASSWORD REQUEST:", email);
    console.log("FRONTEND_URL:", process.env.FRONTEND_URL);
console.log("SENDGRID KEY LOADED:", !!process.env.SENDGRID_API_KEY);
console.log("EMAIL_FROM:", process.env.EMAIL_FROM);
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");

    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 60 * 60 * 1000;
    await user.save();

    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    /* ===== EMAIL DESIGN ===== */
   const resetEmailHTML = `
<!DOCTYPE html>
<html>
<head>
  <style>
    .body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #000000; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 20px auto; background-color: #0a0a0a; border: 1px solid #333; border-radius: 16px; overflow: hidden; }
    .header { background: linear-gradient(to bottom, #3a003a, #000000); padding: 40px 20px; text-align: center; }
    .content { padding: 40px; color: #ffffff; line-height: 1.6; }
    .logo-text { font-size: 24px; font-weight: 900; letter-spacing: 4px; color: #ffffff; text-transform: uppercase; margin: 0; }
    .brand-sub { color: #f59e0b; font-size: 10px; font-weight: bold; text-transform: uppercase; letter-spacing: 2px; margin-top: 5px; }
    .h1 { font-size: 22px; font-weight: bold; margin-bottom: 20px; color: #ffffff; }
    .btn-container { text-align: center; margin: 35px 0; }
    .btn { display: inline-block; padding: 16px 36px; background-color: #2563eb; color: #ffffff !important; text-decoration: none; border-radius: 12px; font-weight: bold; font-size: 16px; transition: background 0.3s; }
    .footer { padding: 30px; background-color: #050505; text-align: center; color: #666; font-size: 12px; border-top: 1px solid #1a1a1a; }
    .warning { font-size: 13px; color: #888; margin-top: 30px; border-top: 1px solid #222; pt: 20px; }
  </style>
</head>
<body class="body">
  <div class="container">
    <div class="header">
      <p class="logo-text">| ASAT</p>
      <div class="brand-sub">Automation Solutions</div>
    </div>
    <div class="content">
      <h1 class="h1">Password Reset Request</h1>
      <p>Hello,</p>
      <p>We received a request to reset the password for your <strong>ASAT Automation</strong> account. To proceed, please click the button below:</p>
      
      <div class="btn-container">
        <a href="${resetLink}" class="btn">Reset My Password</a>
      </div>

      <p>This secure link is valid for <strong>60 minutes</strong>. If you did not make this request, you can safely ignore this email; your account remains secure.</p>
      
      <div class="warning">
        <p>Regards,<br><strong>The ASAT Technical Team</strong></p>
      </div>
    </div>
    <div class="footer">
      &copy; ${new Date().getFullYear()} ASAT Automation. All rights reserved.<br>
      Industrial Solutions for a Modern World.
    </div>
  </div>
</body>
</html>
`;
   try {
  await sendEmail(
    email,
    "Reset your ASAT Automation password",
    resetEmailHTML
  );
  console.log("RESET EMAIL SENT TO:", email);
} catch (emailError) {
  console.error("EMAIL SEND FAILED:", emailError);
  return res.status(500).json({ message: "Email service failed" });
}


    res.json({ message: "Reset email sent" });
  }  catch (err) {
  console.error("FORGOT PASSWORD ERROR:", err);
  res.status(500).json({ message: "Server error", error: err.message });
}

});

/* =========================
   RESET PASSWORD
========================= */
router.post("/reset-password/:token", async (req, res) => {
  try {
    const { newPassword } = req.body;

    const user = await User.findOne({
      resetToken: req.params.token,
      resetTokenExpiry: { $gt: Date.now() },
    });

    if (!user)
      return res.status(400).json({ message: "Invalid or expired token" });

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;

    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (err) {
  console.error("FORGOT PASSWORD ERROR:", err);
  res.status(500).json({ message: "Server error", error: err.message });
}

});
// Update your /users route
router.get("/users", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const currentUser = await User.findById(decoded.id);

    // BLOCK access if they are not an admin
    if (currentUser.role !== "admin") {
      return res.status(403).json({ message: "Admin access required" });
    }

    const users = await User.find().select("-password");
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});
/* =========================
   GET LOGGED IN USER
========================= */
router.get("/me", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (err) {
    console.error("ME ROUTE ERROR:", err.message);
    res.status(401).json({ message: "Invalid token" });
  }
});
module.exports = router;
