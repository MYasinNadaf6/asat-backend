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

    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ message: "User not found" });

    const resetToken = crypto.randomBytes(32).toString("hex");

    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 60 * 60 * 1000; // 15 minutes
    await user.save();

    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    /* ===== EMAIL DESIGN ===== */
    const resetEmailHTML = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <style>
    body {
      background:#f4f6f8;
      font-family: Arial, sans-serif;
    }
    .container {
      max-width:520px;
      margin:40px auto;
      background:#fff;
      border-radius:8px;
      overflow:hidden;
      box-shadow:0 4px 12px rgba(0,0,0,0.1);
    }
    .header {
      background:#1e5eff;
      color:#fff;
      padding:20px;
      text-align:center;
      font-size:22px;
      font-weight:bold;
    }
    .content {
      padding:30px;
      font-size:15px;
      color:#333;
      line-height:1.6;
    }
    .btn {
      display:inline-block;
      margin:25px 0;
      padding:14px 22px;
      color:#dc2626;
      background:Black;
      text-decoration:none;
      border-radius:6px;
      font-weight:bold;
    }
    .footer {
      background:#f0f2f5;
      padding:15px;
      text-align:center;
      font-size:12px;
      color:#777;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">ASAT Automation</div>
    <div class="content">
      <p>Hello,</p>
      <p>You requested a password reset for your ASAT Automation account.</p>
      <p>This link is valid for <strong>60 minutes</strong>.</p>

<div style="text-align:center;">
  <a href="${resetLink}" class="btn">Reset Password</a>
</div>
      <p>If you didn’t request this, ignore this email.</p>

      <p>Regards,<br><strong>ASAT Automation Team</strong></p>
    </div>
    <div class="footer">
      © ${new Date().getFullYear()} ASAT Automation
    </div>
  </div>
</body>
</html>
`;

    await sendEmail(
      email,
      "Reset your ASAT Automation password",
      resetEmailHTML
    );

    res.json({ message: "Reset email sent" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
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
    res.status(500).json({ message: "Server error" });
  }
});
app.get("/api/health", (req, res) => {
  res.status(200).json({ status: "OK", service: "Auth Backend" });
});

module.exports = router;
