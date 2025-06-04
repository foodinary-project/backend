# Foodinary Backend Authentication API

This project provides a simple authentication API using Hapi.js, supporting:

- User registration (`/register`)
- User login (`/login`)
- Password reset via email (`/reset-password`)
- Update Profile (`/update-profile`)

## Tech Stack

- [Hapi.js](https://hapi.dev/) (API framework)
- [Joi](https://joi.dev/) (validation)
- [bcryptjs](https://www.npmjs.com/package/bcryptjs) (password hashing)
- [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken) (JWT auth)
- [nodemailer](https://nodemailer.com/about/) (email sending for password reset)

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
```

## Endpoints

### POST `/register`

**Request Body:**

```
{
  "email": "user@example.com",
  "name": "User Name",
  "password": "Password1",
  "confirmPassword": "Password1"
}
```

### POST `/login`

**Request Body:**

```
{
  "email": "user@example.com",
  "password": "Password1"
}
```

### POST `/reset-password`

**Step 1: Request reset link**

```
{
  "email": "user@example.com"
}
```

**Step 2: Reset password with token**

```
{
  "email": "user@example.com",
  "token": "token-from-email",
  "newPassword": "NewPassword1"
}
```

### PUT `/update-profile`

**Request Body (any field can be updated):**

```
{
  "email": "user@example.com",
  "newEmail": "new@example.com", // optional
  "newName": "New Name",         // optional
  "newPassword": "NewPassword1"  // optional
}
```

## Notes

- Passwords must be at least 8 characters, contain at least one uppercase letter and one number.
- Password reset links are valid for 15 minutes.
- For production, use a persistent database instead of in-memory arrays.
- The password reset email uses Gmail SMTP; you must set up an app password for your Gmail account.
