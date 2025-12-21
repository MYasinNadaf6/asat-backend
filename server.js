require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const authRoutes = require("./routes/auth");
const authMiddleware = require("./middleware/auth");

const app = express();

/* MIDDLEWARE */
app.use(cors({ origin: "*" }));
app.use(express.json());

/* ROUTES */
app.use("/api/auth", authRoutes);

/* HEALTH CHECK */
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", service: "Auth Backend Running" });
});

/* PROTECTED TEST */
app.get("/api/dashboard", authMiddleware, (req, res) => {
  res.json({
    message: "Welcome to protected dashboard",
    userId: req.userId
  });
});

/* START SERVER */
const PORT = process.env.PORT || 5000;

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB Atlas connected");
    app.listen(PORT, () =>
      console.log(`Server running on port ${PORT}`)
    );
  })
  .catch((err) => console.error("MongoDB error:", err));
