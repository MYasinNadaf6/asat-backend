const mongoose = require("mongoose");

const ProductSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  image: { type: String, required: true }, // URL from Cloudinary or similar
  category: { type: String },
  price: { type: String }
}, { timestamps: true });

module.exports = mongoose.model("Product", ProductSchema);