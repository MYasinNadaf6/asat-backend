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
<body>
  <div class="container">
    <div class="header">ASAT Automation</div>
    <div class="content">
      <p>Hello,</p>
      <p>You requested a password reset for your ASAT Automation account.</p>
      <p>This link is valid for <strong>60 minutes</strong>.</p>

<div style="text-align:center; margin:25px 0;">
  <a href="${resetLink}"
     style="
       display:inline-block;
       padding:14px 26px;
       background:#1e40af;
       color:#ffffff !important;
       text-decoration:none;
       border-radius:8px;
       font-size:16px;
       font-weight:600;
       font-family:Arial, sans-serif;
     ">
     Reset Password
  </a>
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

// GET logged-in user
router.get("/me", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ message: "No token" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

module.exports = router;
