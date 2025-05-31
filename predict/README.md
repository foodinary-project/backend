# Foodinary Predict Backend

This is an Express.js backend for Indonesian traditional cuisine recipe prediction. It provides endpoints for image-based prediction, user history, favorites, and recipe retrieval.

## Endpoints

- `GET /history` — Get user prediction history
- `DELETE /delete-history` — Delete user prediction history
- `GET /favorites` — Get user favorite recipes
- `PUT /favorites` — Add or update user favorite recipes
- `POST /prediction` — Upload an image, get prediction and recipe
- `GET /recipes/:id` — Get recipe details by ID

## Features

- Image upload with multer
- Calls external ML model API for prediction
- In-memory storage for history, favorites, and recipes (can be replaced with a database)

## Getting Started

1. Install dependencies:
   ```bash
   npm install
   ```
2. Start the server:
   ```bash
   node index.js
   ```

## Notes

- Replace the ML model endpoint URL in the code with your deployed model's URL.
- This project is for demonstration and prototyping. For production, use persistent storage and add authentication.
