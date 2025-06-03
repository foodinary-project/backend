# Foodinary Backend Authentication API

This project provides a simple authentication API using Hapi.js, supporting:

- User registration (`/register`)
- User login (`/login`)
- Password reset (`/reset-password`)
- Update Profile (`/update-profile`)

## Tech Stack

- [Hapi.js](https://hapi.dev/) (API framework)
- [Joi](https://joi.dev/) (validation)
- [bcryptjs](https://www.npmjs.com/package/bcryptjs) (password hashing)
- [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken) (JWT auth)

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

## Endpoints

- **POST /register**: `{ username, password }`
- **POST /login**: `{ username, password }`
- **POST /reset-password**: `{ username, newPassword }`
- **PUT /update-profile**: `{ }`
