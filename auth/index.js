// Use require('dotenv').config() only in development.
if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

const Hapi = require("@hapi/hapi");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { Storage } = require("@google-cloud/storage");
const { Pool } = require("pg"); // Import the pg Pool

// --- Load configuration from environment variables ---
const JWT_SECRET = process.env.JWT_SECRET;
const GCS_BUCKET_NAME = process.env.GCS_BUCKET_NAME;
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_PASS = process.env.GMAIL_PASS;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:8080";
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";
const DATABASE_URL = process.env.DATABASE_URL; // Get the database URL from Render

// --- Service Initialization ---
let storage;
try {
  storage = new Storage();
  console.log("Google Cloud Storage client initialized successfully.");
} catch (error) {
  console.error("Could not initialize Google Cloud Storage client.", error);
}

// --- NEW: Database Connection Pool ---
// The Pool will use the DATABASE_URL environment variable to connect.
// For production on Render with a free plan, you may need SSL.
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: GMAIL_USER, pass: GMAIL_PASS },
});

// Helper function remains the same
const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
};

const init = async () => {
  // Pre-flight checks
  if (!JWT_SECRET || !DATABASE_URL) {
    console.error(
      "FATAL ERROR: JWT_SECRET and DATABASE_URL environment variables must be set."
    );
    process.exit(1);
  }

  // Test the database connection on startup
  try {
    const client = await pool.connect();
    console.log("Database connected successfully.");
    client.release(); // Release the client back to the pool
  } catch (error) {
    console.error("FATAL ERROR: Failed to connect to the database.", error);
    process.exit(1);
  }

  const server = Hapi.server({
    port: PORT,
    host: HOST,
    routes: {
      cors: {
        origin: ["http://localhost:5173", FRONTEND_URL].filter(Boolean),
        headers: [
          "Accept",
          "Authorization",
          "Content-Type",
          "If-None-Match",
          "X-File-Name",
          "X-File-Type",
        ],
        credentials: true,
      },
    },
  });

  // --- MODIFIED ROUTES ---

  // REGISTER
  server.route({
    method: "POST",
    path: "/register",
    options: {
      // Validation stays the same
      validate: {
        payload: Joi.object({
          /* ... */
        }),
      },
    },
    handler: async (request, h) => {
      const { email, name, password } = request.payload;

      try {
        // Check if user already exists in the database
        const userCheck = await pool.query(
          "SELECT * FROM users WHERE email = $1",
          [email]
        );
        if (userCheck.rows.length > 0) {
          return h
            .response({ statusCode: 409, message: "Email already exists" })
            .code(409);
        }

        // Hash password and insert new user
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUserQuery =
          "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email, name";
        const result = await pool.query(newUserQuery, [
          name,
          email,
          hashedPassword,
        ]);

        return h
          .response({
            statusCode: 201,
            message: "User registered successfully",
            user: result.rows[0],
          })
          .code(201);
      } catch (err) {
        console.error("Error during registration:", err);
        return h
          .response({ statusCode: 500, message: "Internal Server Error" })
          .code(500);
      }
    },
  });

  // LOGIN
  server.route({
    method: "POST",
    path: "/login",
    options: {
      // Validation stays the same
      validate: {
        payload: Joi.object({
          /* ... */
        }),
      },
    },
    handler: async (request, h) => {
      const { email, password } = request.payload;

      try {
        const result = await pool.query(
          "SELECT * FROM users WHERE email = $1",
          [email]
        );
        const user = result.rows[0];

        if (!user) {
          return h
            .response({ statusCode: 401, message: "Invalid email or password" })
            .code(401);
        }

        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
          return h
            .response({ statusCode: 401, message: "Invalid email or password" })
            .code(401);
        }

        const token = jwt.sign(
          { userId: user.id, email: user.email, name: user.name },
          JWT_SECRET,
          { expiresIn: "1h" }
        );

        return {
          token,
          message: "Login successfully",
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            profilePictureUrl: user.profile_picture_url || null,
          },
        };
      } catch (err) {
        console.error("Error during login:", err);
        return h
          .response({ statusCode: 500, message: "Internal Server Error" })
          .code(500);
      }
    },
  });

  // UPDATE PROFILE
  server.route({
    method: "PUT",
    path: "/update-profile",
    options: {
      // Validation stays the same
      validate: {
        headers: Joi.object({
          /* ... */
        }),
        payload: Joi.object({
          /* ... */
        }),
      },
    },
    handler: async (request, h) => {
      const decodedToken = verifyToken(
        request.headers.authorization.substring(7)
      );
      if (!decodedToken) {
        return h
          .response({ statusCode: 401, message: "Invalid or expired token" })
          .code(401);
      }

      const userId = decodedToken.userId;
      const { newEmail, newName, newProfilePictureUrl } = request.payload;

      try {
        // Dynamically build the UPDATE query based on what fields are provided
        const fields = [];
        const values = [];
        let paramIndex = 1;

        if (newName) {
          fields.push(`name = $${paramIndex++}`);
          values.push(newName);
        }
        if (newEmail) {
          fields.push(`email = $${paramIndex++}`);
          values.push(newEmail);
        }
        if (newProfilePictureUrl !== undefined) {
          fields.push(`profile_picture_url = $${paramIndex++}`);
          values.push(newProfilePictureUrl);
        }

        if (fields.length === 0) {
          return h
            .response({ statusCode: 400, message: "No fields to update" })
            .code(400);
        }

        values.push(userId); // Add userId for the WHERE clause
        const updateQuery = `UPDATE users SET ${fields.join(
          ", "
        )} WHERE id = $${paramIndex} RETURNING id, email, name, profile_picture_url`;

        const result = await pool.query(updateQuery, values);

        if (result.rows.length === 0) {
          return h
            .response({ statusCode: 404, message: "User not found" })
            .code(404);
        }

        return h
          .response({
            statusCode: 200,
            message: "Profile updated successfully",
            user: result.rows[0],
          })
          .code(200);
      } catch (err) {
        console.error("Error updating profile:", err);
        // Handle specific error for unique email violation
        if (err.code === "23505") {
          // PostgreSQL unique violation error code
          return h
            .response({ statusCode: 409, message: "Email already in use" })
            .code(409);
        }
        return h
          .response({ statusCode: 500, message: "Internal Server Error" })
          .code(500);
      }
    },
  });

  // GET PROFILE
  server.route({
    method: "GET",
    path: "/profile",
    options: {
      validate: {
        headers: Joi.object({
          authorization: Joi.string().required(), // Expect JWT in Authorization header
        }).unknown(true), // Allow other headers
        failAction: (request, h, err) => {
          return h
            .response({ statusCode: 400, message: err.details[0].message })
            .code(400)
            .takeover();
        },
      },
    },
    handler: (request, h) => {
      const authHeader = request.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return h
          .response({
            statusCode: 401,
            message: "Missing or invalid token format",
          })
          .code(401);
      }
      const token = authHeader.substring(7);
      const decodedToken = verifyToken(token);

      if (!decodedToken || !decodedToken.email) {
        return h
          .response({ statusCode: 401, message: "Invalid or expired token" })
          .code(401);
      }

      const user = users.find((u) => u.email === decodedToken.email);
      if (!user) {
        return h
          .response({ statusCode: 404, message: "User not found" })
          .code(404);
      }

      return h
        .response({
          statusCode: 200,
          message: "Profile retrieved successfully",
          user: {
            email: user.email,
            name: user.name,
            profilePictureUrl: user.profilePictureUrl || null,
          },
        })
        .code(200);
    },
  });

  // (Your other routes like /reset-password and /generate-upload-url can remain largely the same,
  // as they don't directly interact with the persistent user data in the same way)

  // --- Server Start ---
  await server.start();
  console.log("Server running on %s", server.info.uri);
};

init();
