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
const DATABASE_URL = process.env.DATABASE_URL;

// --- Service Initialization ---
let storage;
try {
  storage = new Storage();
  console.log("Google Cloud Storage client initialized successfully.");
} catch (error) {
  console.error("Could not initialize Google Cloud Storage client.", error);
}

// Database Connection Pool
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

// Helper function
const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
};

// --- In-memory store for reset tokens. For production, this could also be moved to the database.
const resetTokens = {};

const init = async () => {
  // Pre-flight checks
  if (!JWT_SECRET || !DATABASE_URL) {
    console.error("FATAL ERROR: JWT_SECRET and DATABASE_URL must be set.");
    process.exit(1);
  }

  try {
    const client = await pool.connect();
    console.log("Database connected successfully.");
    client.release();
  } catch (error) {
    console.error("FATAL ERROR: Failed to connect to the database.", error);
    process.exit(1);
  }

  const server = Hapi.server({
    port: PORT,
    host: HOST,
    routes: {
      cors: {
        origin: [
          "http://localhost:5173",
          "http://localhost:3000",
          "http://localhost:8080",
          FRONTEND_URL,
        ].filter(Boolean),
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

  // --- ROUTES ---

  // REGISTER
  server.route({
    method: "POST",
    path: "/register",
    options: {
      validate: {
        payload: Joi.object({
          email: Joi.string().email().required(),
          name: Joi.string().min(2).required(),
          password: Joi.string()
            .min(8)
            .pattern(new RegExp("^(?=.*[A-Z])(?=.*\\d).+$"))
            .required()
            .messages({
              "string.pattern.base":
                "Password must contain at least one uppercase letter and one number",
            }),
          confirmPassword: Joi.string()
            .valid(Joi.ref("password"))
            .required()
            .messages({
              "any.only": "Password confirmation does not match password",
            }),
        }),
        failAction: (request, h, err) =>
          h
            .response({ statusCode: 400, message: err.details[0].message })
            .code(400)
            .takeover(),
      },
    },
    handler: async (request, h) => {
      const { email, name, password } = request.payload;
      try {
        const userCheck = await pool.query(
          "SELECT id FROM users WHERE email = $1",
          [email]
        );
        if (userCheck.rows.length > 0) {
          return h
            .response({ statusCode: 409, message: "Email already exists" })
            .code(409);
        }
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
      validate: {
        payload: Joi.object({
          email: Joi.string().email().required(),
          password: Joi.string().required(),
        }),
        failAction: (request, h, err) =>
          h
            .response({ statusCode: 400, message: err.details[0].message })
            .code(400)
            .takeover(),
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
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
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

  // GET PROFILE
  server.route({
    method: "GET",
    path: "/profile",
    options: {
      validate: {
        headers: Joi.object({ authorization: Joi.string().required() }).unknown(
          true
        ),
        failAction: (request, h, err) =>
          h
            .response({ statusCode: 400, message: err.details[0].message })
            .code(400)
            .takeover(),
      },
    },
    handler: async (request, h) => {
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

      if (!decodedToken || !decodedToken.userId) {
        return h
          .response({ statusCode: 401, message: "Invalid or expired token" })
          .code(401);
      }
      try {
        const result = await pool.query(
          "SELECT id, email, name, profile_picture_url FROM users WHERE id = $1",
          [decodedToken.userId]
        );
        if (result.rows.length === 0) {
          return h
            .response({ statusCode: 404, message: "User not found" })
            .code(404);
        }
        const user = result.rows[0];
        return {
          statusCode: 200,
          message: "Profile retrieved successfully",
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            profilePictureUrl: user.profile_picture_url || null,
          },
        };
      } catch (err) {
        console.error("Error fetching profile:", err);
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
      validate: {
        headers: Joi.object({ authorization: Joi.string().required() }).unknown(
          true
        ),
        payload: Joi.object({
          newEmail: Joi.string().email().optional(),
          newName: Joi.string().min(2).optional(),
          newProfilePictureUrl: Joi.string().uri().allow(null, "").optional(),
        }),
        failAction: (request, h, err) =>
          h
            .response({ statusCode: 400, message: err.details[0].message })
            .code(400)
            .takeover(),
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
        const fields = [],
          values = [];
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
        values.push(userId);
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
        if (err.code === "23505")
          return h
            .response({ statusCode: 409, message: "Email already in use" })
            .code(409);
        return h
          .response({ statusCode: 500, message: "Internal Server Error" })
          .code(500);
      }
    },
  });

  // RESET PASSWORD (Kept in-memory for simplicity, can be moved to DB)
  server.route({
    method: "POST",
    path: "/reset-password",
    options: {
      validate: {
        payload: Joi.object({
          email: Joi.string().email().required(),
          token: Joi.string().optional(),
          newPassword: Joi.string()
            .min(8)
            .pattern(new RegExp("^(?=.*[A-Z])(?=.*\\d).+$"))
            .optional()
            .messages({
              "string.pattern.base":
                "Password must contain at least one uppercase letter and one number",
            }),
        }),
        failAction: (request, h, err) =>
          h
            .response({ statusCode: 400, message: err.details[0].message })
            .code(400)
            .takeover(),
      },
    },
    handler: async (request, h) => {
      const { email, token, newPassword } = request.payload;
      if (!token && !newPassword) {
        // Requesting reset link
        const result = await pool.query(
          "SELECT id FROM users WHERE email = $1",
          [email]
        );
        if (result.rows.length === 0)
          return h
            .response({
              message:
                "If a user with this email exists, a reset link has been sent.",
            })
            .code(200); // Don't reveal if email exists
        const resetToken = crypto.randomBytes(32).toString("hex");
        resetTokens[email] = {
          token: resetToken,
          expires: Date.now() + 15 * 60 * 1000,
        };
        const resetLink = `${FRONTEND_URL}/reset-password?email=${encodeURIComponent(
          email
        )}&token=${resetToken}`;
        try {
          await transporter.sendMail({
            from: `"${
              process.env.APP_NAME ||
              "Foodinary | Find Your Indonesia Recipe Here!"
            }" <foodinary.project@gmail.com>`,
            to: email,
            subject: "Password Reset Request",
            text: `Click here to reset: ${resetLink}`,
          });
        } catch (err) {
          console.error(err);
        }
        return h
          .response({
            message:
              "If a user with this email exists, a reset link has been sent.",
          })
          .code(200);
      } else if (token && newPassword) {
        // Submitting new password
        const record = resetTokens[email];
        if (!record || record.token !== token || record.expires < Date.now()) {
          return h
            .response({ message: "Invalid or expired reset token" })
            .code(400);
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query(
          "UPDATE users SET password_hash = $1 WHERE email = $2",
          [hashedPassword, email]
        );
        delete resetTokens[email];
        return { message: "Password has been reset successfully." };
      }
      return h.response({ message: "Invalid request" }).code(400);
    },
  });

  // GENERATE UPLOAD URL
  server.route({
    method: "POST",
    path: "/generate-upload-url",
    options: {
      validate: {
        headers: Joi.object({ authorization: Joi.string().required() }).unknown(
          true
        ),
        payload: Joi.object({
          fileName: Joi.string().required(),
          contentType: Joi.string().required(),
        }),
        failAction: (request, h, err) =>
          h
            .response({ statusCode: 400, message: err.details[0].message })
            .code(400)
            .takeover(),
      },
    },
    handler: async (request, h) => {
      if (!storage || !GCS_BUCKET_NAME) {
        return h
          .response({
            statusCode: 500,
            message: "Cloud storage not configured",
          })
          .code(500);
      }
      const decodedToken = verifyToken(
        request.headers.authorization.substring(7)
      );
      if (!decodedToken) {
        return h
          .response({ statusCode: 401, message: "Unauthorized" })
          .code(401);
      }
      const { fileName, contentType } = request.payload;
      const uniqueFileName = `${
        decodedToken.userId
      }-${Date.now()}-${fileName.replace(/\s+/g, "_")}`;
      const options = {
        version: "v4",
        action: "write",
        expires: Date.now() + 15 * 60 * 1000,
        contentType,
      };
      try {
        const [url] = await storage
          .bucket(GCS_BUCKET_NAME)
          .file(uniqueFileName)
          .getSignedUrl(options);
        return {
          statusCode: 200,
          uploadUrl: url,
          publicUrl: `https://storage.googleapis.com/${GCS_BUCKET_NAME}/${uniqueFileName}`,
        };
      } catch (error) {
        console.error("Failed to generate signed URL:", error);
        return h
          .response({
            statusCode: 500,
            message: "Failed to generate upload URL.",
          })
          .code(500);
      }
    },
  });

  // --- Server Start ---
  try {
    await server.start();
    console.log("Server running on %s", server.info.uri);
  } catch (err) {
    console.error("Error starting server:", err);
    process.exit(1);
  }
};

init();
