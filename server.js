require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const app = express();

/* 1. MIDDLEWARE */
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: '50mb' }));

/* 2. HEALTH CHECK ROUTE */
app.get("/api/health", (req, res) => {
  res.status(200).json({
    status: "Active",
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

/* 3. DATABASE MODELS */
const ProductSchema = new mongoose.Schema({
  title: String,
  image: String,
  description: String,
  category: { type: String, default: "Industrial Automation" },
  // Added technical specs object
  specs: {
    tableSize: { type: String, default: "N/A" },
    spindleSpeed: { type: String, default: "N/A" },
    powerRating: { type: String, default: "N/A" },
    accuracy: { type: String, default: "N/A" }
  }
}, { timestamps: true });

const Product = mongoose.model("Product", ProductSchema);

/* 4. ROUTES */
app.use("/api/auth", require("./routes/auth"));

// GET all products
app.get("/api/products/all", async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

// GET single product
app.get("/api/products/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });
    res.json(product);
  } catch (err) {
    res.status(500).json({ error: "Invalid ID" });
  }
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

// UPDATE a product
app.put("/api/products/update/:id", async (req, res) => {
  try {
    const updatedProduct = await Product.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    res.json(updatedProduct);
  } catch (err) {
    res.status(500).json({ error: "Update failed" });
  }
});

// DELETE a product
app.delete("/api/products/:id", async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: "Product deleted" }); 
  } catch (err) 
  
  {
    res.status(500).json({ error: "Failed to delete" });
  }
});

/* 5. DATABASE CONNECTION */
const PORT = process.env.PORT || 5000;
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB Atlas connected");
    app.listen(PORT, () => console.log(`🚀 ASAT Server running on port ${PORT}`));
  })
  .catch((err) => console.error("❌ MongoDB connection error:", err));