require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const app = express();

/* 1. MIDDLEWARE */
app.use(cors({ origin: "*" }));
app.use(express.json());

/* 2. UPTIME ROBOT / HEALTH CHECK ROUTE */
// This is the URL you will give to UptimeRobot: https://your-app.com/api/health
app.get("/api/health", (req, res) => {
  const statusData = {
    status: "Active",
    uptime: process.uptime(), // Shows how long the server has been running
    message: "ASAT Automation Backend is Live",
    timestamp: new Date().toISOString()
  };
  
  console.log(`Ping received from UptimeRobot at: ${statusData.timestamp}`);
  res.status(200).json(statusData);
});

/* 3. DATABASE MODELS (Example for your Dynamic Products) */
const ProductSchema = new mongoose.Schema({
  title: String,
  image: String,
  description: String,
  category: String
});
const Product = mongoose.model("Product", ProductSchema);

/* 4. ROUTES */
app.use("/api/auth", require("./routes/auth"));

// Dynamic Products Route
app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

/* 5. DATABASE CONNECTION & START */
const PORT = process.env.PORT || 5000;

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB Atlas connected");
    app.listen(PORT, () => {
      console.log(`🚀 ASAT Server running on port ${PORT}`);
      console.log(`📡 Health Check available at: http://localhost:${PORT}/api/health`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
  });

  // POST a new product
app.post("/api/products/add", async (req, res) => {
  try {
    const newProduct = new Product(req.body);
    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (err) {
    res.status(500).json({ error: "Failed to add product" });
  }
});

// DELETE a product
app.delete("/api/products/:id", async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: "Product deleted" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete" });
  }
});