const express = require("express");
const router = express.Router();
const Product = require("../models/Product");

// POST: Add a new product (Used by Admin Panel)
router.post("/add", async (req, res) => {
  try {
    const newProduct = new Product(req.body);
    const savedProduct = await newProduct.save();
    res.status(201).json(savedProduct);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET: Fetch all products (Used by Products.jsx)
router.get("/all", async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// backend/routes/productRoutes.js
router.get("/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Machine not found" });
    res.json(product);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


module.exports = router;