# Foodinary Backend Authentication & Prediction API

This project provides a backend API for Foodinary, focusing on Indonesian traditional cuisine. It supports:

- User registration and authentication
- Password reset via email
- Profile management
- Image-based cuisine prediction using a deployed machine learning model
- User prediction history and favorites management

## Tech Stack

- [Hapi.js](https://hapi.dev/) (API framework)
- [Joi](https://joi.dev/) (validation)
- [bcryptjs](https://www.npmjs.com/package/bcryptjs) (password hashing)
- [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken) (JWT auth)
- [nodemailer](https://nodemailer.com/about/) (email sending for password reset)
- [@google-cloud/storage](https://www.npmjs.com/package/@google-cloud/storage) (profile picture upload)
- [pg](https://www.npmjs.com/package/pg) (PostgreSQL database)

## Usage

1. Install dependencies:
   ```bash
   npm install
   ```
2. Start the server:
   ```bash
   node index.js
   ```
3. The API will be available at `http://localhost:3000`.

## Environment Variables

Create a `.env` file in the project root with:

```
GMAIL_USER=your-gmail-address@gmail.com
GMAIL_PASS=your-gmail-app-password
HOST=localhost
GCS_BUCKET_NAME=your-gcs-bucket
GOOGLE_APPLICATION_CREDENTIALS=your-gcs-credentials.json
DATABASE_URL=your-postgres-connection-string
JWT_SECRET=your-jwt-secret
```

## Endpoints

### Authentication & Profile

- `POST /register` — Register a new user
- `POST /login` — User login
- `POST /reset-password` — Request/reset password via email
- `GET /profile` — Get user profile (JWT required)
- `PUT /update-profile` — Update user profile (JWT required)

### Prediction & Recipe

- `POST /prediction` — Upload an image, get cuisine prediction and recipe
  - **Request:** `multipart/form-data` with an image file
  - **Response:**
    ```json
    {
      "prediction": "Rendang",
      "confidence": 0.98,
      "recipe": { "title": "Rendang", "ingredients": [...], "steps": [...] }
    }
    ```

### History

- `GET /history` — Get user's prediction history (JWT required)
- `DELETE /delete-history` — Delete user's prediction history (JWT required)

### Favorites

- `GET /favorites` — Get user's favorite recipes (JWT required)
- `PUT /favorites` — Add or update user's favorite recipes (JWT required)

## ML Model Integration

- The `/prediction` endpoint accepts an image from the user, sends it to the deployed ML model API, and returns the predicted cuisine and its recipe.
- You must set the ML model API URL in your environment/configuration.

## Notes

- Passwords must be at least 8 characters, contain at least one uppercase letter and one number.
- Password reset links are valid for 15 minutes.
- For production, use a persistent database instead of in-memory arrays.
- The password reset email uses Gmail SMTP; you must set up an app password for your Gmail account.
- For image upload and prediction, ensure your ML model endpoint is accessible and accepts image data.
