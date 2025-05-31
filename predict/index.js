const express = require("express");
const multer = require("multer");
const axios = require("axios");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());

// In-memory storage
let history = [];
let favorites = [];
let recipes = [
  // Example recipe objects
  {
    id: 1,
    name: "Rendang",
    ingredients: ["beef", "coconut milk", "spices"],
    steps: ["..."],
  },
  {
    id: 2,
    name: "Sate Ayam",
    ingredients: ["chicken", "peanut sauce"],
    steps: ["..."],
  },
];

// Multer setup for image upload
const storage = multer.memoryStorage();
const upload = multer({ storage });

// GET /history
app.get("/history", (req, res) => {
  res.json({ history });
});

// DELETE /delete-history
app.delete("/delete-history", (req, res) => {
  history = [];
  res.json({ message: "History deleted" });
});

// GET /favorites
app.get("/favorites", (req, res) => {
  res.json({ favorites });
});

// PUT /favorites
app.put("/favorites", (req, res) => {
  const { recipeId } = req.body;
  if (!favorites.includes(recipeId)) {
    favorites.push(recipeId);
  }
  res.json({ favorites });
});

// GET /recipes/:id
app.get("/recipes/:id", (req, res) => {
  const recipe = recipes.find((r) => r.id === parseInt(req.params.id));
  if (!recipe) return res.status(404).json({ message: "Recipe not found" });
  res.json({ recipe });
});

// POST /prediction
app.post("/prediction", upload.single("image"), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: "No image uploaded" });

  try {
    // Replace with your deployed ML model endpoint
    const mlEndpoint = "https://your-ml-model-endpoint/predict";
    const response = await axios.post(mlEndpoint, req.file.buffer, {
      headers: { "Content-Type": "application/octet-stream" },
    });
    const prediction = response.data;

    // Find recipe by predicted label (assume prediction.label)
    const recipe = recipes.find(
      (r) => r.name.toLowerCase() === prediction.label.toLowerCase()
    );
    // Add to history
    history.push({
      image: req.file.originalname,
      prediction: prediction.label,
      date: new Date(),
    });

    res.json({ prediction: prediction.label, recipe });
  } catch (err) {
    res.status(500).json({ message: "Prediction failed", error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
