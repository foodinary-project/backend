// Use dotenv for development. In production, environment variables are set directly.
import 'dotenv/config';

import Hapi from '@hapi/hapi';
import Joi from 'joi';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import pg from 'pg';
import axios from 'axios';
import { v2 as cloudinary } from 'cloudinary'; // NEW: Import Cloudinary
import { client as GradioClient } from '@gradio/client';

// Import JSON data with an import assertion
import recipeData from './recipes.json' with { type: 'json' };

const { Pool } = pg;

// --- Load configuration from environment variables ---
const JWT_SECRET = process.env.JWT_SECRET;
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_PASS = process.env.GMAIL_PASS;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:8080";
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";
const DATABASE_URL = process.env.DATABASE_URL;
const HUGGING_FACE_SPACE = process.env.HUGGING_FACE_SPACE;

// --- NEW: Cloudinary Configuration ---
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

cloudinary.config({
  cloud_name: CLOUDINARY_CLOUD_NAME,
  api_key: CLOUDINARY_API_KEY,
  api_secret: CLOUDINARY_API_SECRET,
  secure: true,
});


// --- Transform recipe array into a searchable object ---
const recipes = recipeData.recipes.reduce((acc, recipe) => {
    const key = recipe.name.toLowerCase().replace(/\s+/g, ' ');
    acc[key] = recipe;
    return acc;
}, {});

// In-memory store for reset codes.
const resetTokens = {};

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
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

const init = async () => {
  // Updated pre-flight checks for new environment variables
  if (!JWT_SECRET || !DATABASE_URL || !HUGGING_FACE_SPACE || !CLOUDINARY_CLOUD_NAME || !CLOUDINARY_API_KEY || !CLOUDINARY_API_SECRET) {
    console.error("FATAL ERROR: All required environment variables (JWT, DB, HuggingFace, Cloudinary) must be set.");
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
          "https://dainty-palmier-676868.netlify.app",
           FRONTEND_URL
        ].filter(Boolean),
        headers: ["Accept", "Authorization", "Content-Type", "If-None-Match", "X-File-Name", "X-File-Type"],
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
              password: Joi.string().min(8).pattern(new RegExp("^(?=.*[A-Z])(?=.*\\d).+$")).required().messages({
                  "string.pattern.base": "Password must contain at least one uppercase letter and one number",
              }),
              confirmPassword: Joi.string().valid(Joi.ref("password")).required().messages({
                  "any.only": "Password confirmation does not match password",
              }),
            }),
            failAction: (request, h, err) => h.response({ statusCode: 400, message: err.details[0].message }).code(400).takeover(),
          },
        },
        handler: async (request, h) => {
          const { email, name, password } = request.payload;
          try {
            const userCheck = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
            if (userCheck.rows.length > 0) {
              return h.response({ statusCode: 409, message: "Email already exists" }).code(409);
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            const newUserQuery = "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email, name";
            const result = await pool.query(newUserQuery, [name, email, hashedPassword]);
            return h.response({ statusCode: 201, message: "User registered successfully", user: result.rows[0] }).code(201);
          } catch (err) {
            console.error("Error during registration:", err);
            return h.response({ statusCode: 500, message: "Internal Server Error" }).code(500);
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
            failAction: (request, h, err) => h.response({ statusCode: 400, message: err.details[0].message }).code(400).takeover(),
          },
        },
        handler: async (request, h) => {
          const { email, password } = request.payload;
          try {
            const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
            const user = result.rows[0];
            if (!user || !(await bcrypt.compare(password, user.password_hash))) {
              return h.response({ statusCode: 401, message: "Invalid email or password" }).code(401);
            }
            const token = jwt.sign({ userId: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
            return {
              token,
              message: "Login successfully",
              user: { id: user.id, email: user.email, name: user.name, profilePictureUrl: user.profile_picture_url || null },
            };
          } catch (err) {
            console.error("Error during login:", err);
            return h.response({ statusCode: 500, message: "Internal Server Error" }).code(500);
          }
        },
    });

    // GET PROFILE
    server.route({
        method: "GET",
        path: "/profile",
        options: {
          validate: {
            headers: Joi.object({ authorization: Joi.string().required() }).unknown(true),
            failAction: (request, h, err) => h.response({ statusCode: 400, message: err.details[0].message }).code(400).takeover(),
          },
        },
        handler: async (request, h) => {
          const authHeader = request.headers.authorization;
          if (!authHeader || !authHeader.startsWith("Bearer ")) { return h.response({ statusCode: 401, message: "Missing or invalid token format" }).code(401); }
          const token = authHeader.substring(7);
          const decodedToken = verifyToken(token);
          if (!decodedToken || !decodedToken.userId) { return h.response({ statusCode: 401, message: "Invalid or expired token" }).code(401); }
          try {
            const result = await pool.query("SELECT id, email, name, profile_picture_url FROM users WHERE id = $1", [decodedToken.userId]);
            if (result.rows.length === 0) { return h.response({ statusCode: 404, message: "User not found" }).code(404); }
            const user = result.rows[0];
            return { statusCode: 200, message: "Profile retrieved successfully", user: { id: user.id, email: user.email, name: user.name, profilePictureUrl: user.profile_picture_url || null } };
          } catch (err) {
            console.error("Error fetching profile:", err);
            return h.response({ statusCode: 500, message: "Internal Server Error" }).code(500);
          }
        },
    });

    // RESET PASSWORD
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
          "SELECT id, name FROM users WHERE email = $1",
          [email]
        );
        if (result.rows.length === 0)
          return h
            .response({
              message:
                "If a user with this email exists, a reset link has been sent.",
            })
            .code(200); // Don't reveal if email exists

        const userName = result.rows[0].name || "there";
        const resetToken = Math.floor(10000 + Math.random() * 90000).toString();
        resetTokens[email] = {
          token: resetToken,
          expires: Date.now() + 15 * 60 * 1000,
        };
        const resetLink = `${FRONTEND_URL}/reset-password?email=${encodeURIComponent(
          email
        )}&token=${resetToken}`;

        // Styled email with highlighted token and link
        const emailText = `Hi ${userName},

          We received a request to reset the password for your account associated with this email address.

          To reset your password, please use the following token:

          ==============================
          🔑 Reset Token: *${resetToken}*
          ==============================

          Or, you can simply click the button below:

          ==============================
          ${resetLink}
          ==============================

          If you didn’t request this, you can safely ignore this email. Your password will remain unchanged.

          ---

          Best regards,  
          The Foodinary Team  
          foodinary.project@gmail.com | https://foodinary.com`;
        try {
          await transporter.sendMail({
            from: `"${
              process.env.APP_NAME ||
              "Foodinary | Find Your Indonesia Recipe Here!"
            }" <foodinary.project@gmail.com>`,
            to: email,
            subject: "Password Reset Request",
            text: emailText,
            html: `<div style="font-family:sans-serif;line-height:1.6">
                     <p>Hi <b>${userName}</b>,</p>
                     <p>We received a request to reset the password for your account associated with this email address.</p>
                     <p>To reset your password, please use the following token:</p>
                     <div style="background:#f5f5f5;border-radius:6px;padding:16px 24px;font-size:1.2em;display:inline-block;margin:12px 0;">
                       <b>🔑 Reset Token: <span style="color:#1976d2;font-size:1.3em;">${resetToken}</span></b>
                     </div>
                     <p>Or, you can simply click the button below:</p>
                     <a href="${resetLink}" style="display:inline-block;background:#1976d2;color:#fff;text-decoration:none;padding:12px 24px;border-radius:4px;font-weight:bold;margin:12px 0;">Reset Password</a>
                     <p>If you didn’t request this, you can safely ignore this email. Your password will remain unchanged.</p>
                     <hr>
                     <p style="font-size:0.95em;">
                       Best regards,<br>
                       The Foodinary Team<br>
                       <a href="mailto:foodinary.project@gmail.com" style="color:#1976d2">foodinary.project@gmail.com</a> | <a href="https://foodinary.com" style="color:#1976d2">https://foodinary.com</a>
                     </p>
                   </div>`,
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

    // UPDATE PROFILE
    server.route({
        method: "PUT",
        path: "/update-profile",
        options: {
          validate: {
            headers: Joi.object({ authorization: Joi.string().required() }).unknown(true),
            payload: Joi.object({
              newName: Joi.string().min(2).optional(),
              newEmail: Joi.string().email().optional(),
              newProfilePictureUrl: Joi.string().uri().allow(null, "").optional(),
              oldPassword: Joi.string().min(8).optional(),
              newPassword: Joi.string().min(8).pattern(new RegExp("^(?=.*[A-Z])(?=.*\\d).+$")).optional().messages({
                "string.pattern.base": "Password must contain at least one uppercase letter and one number",
              }),
              confirmNewPassword: Joi.string().valid(Joi.ref('newPassword')).when('newPassword', {
                is: Joi.exist(),
                then: Joi.required().messages({
                  'any.only': 'Password confirmation does not match new password',
                  'any.required': 'Password confirmation is required when changing password'
                }),
                otherwise: Joi.optional()
              })
            }),
            failAction: (request, h, err) => h.response({ statusCode: 400, message: err.details[0].message }).code(400).takeover(),
          },
        },
        handler: async (request, h) => {
            const decodedToken = verifyToken(request.headers.authorization.substring(7));
            if (!decodedToken) { return h.response({ statusCode: 401, message: "Invalid or expired token" }).code(401); }
            const userId = decodedToken.userId;
            const { newEmail, newName, newProfilePictureUrl, oldPassword, newPassword } = request.payload;
            try {
                // If newPassword is provided, oldPassword must be provided and correct
                if (newPassword) {
                    if (!oldPassword) {
                        return h.response({ statusCode: 400, message: "Old password is required to set a new password" }).code(400);
                    }
                    const userResult = await pool.query("SELECT password_hash FROM users WHERE id = $1", [userId]);
                    if (userResult.rows.length === 0) {
                        return h.response({ statusCode: 404, message: "User not found" }).code(404);
                    }
                    const validOld = await bcrypt.compare(oldPassword, userResult.rows[0].password_hash);
                    if (!validOld) {
                        return h.response({ statusCode: 401, message: "Old password is incorrect" }).code(401);
                    }
                }
                const fields = [], values = []; let paramIndex = 1;
                if (newName) { fields.push(`name = $${paramIndex++}`); values.push(newName); }
                if (newEmail) { fields.push(`email = $${paramIndex++}`); values.push(newEmail); }
                if (newProfilePictureUrl !== undefined) { fields.push(`profile_picture_url = $${paramIndex++}`); values.push(newProfilePictureUrl); }
                if (newPassword) {
                    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
                    fields.push(`password_hash = $${paramIndex++}`); values.push(hashedNewPassword);
                }
                if (fields.length === 0) { return h.response({ statusCode: 400, message: "No fields to update" }).code(400); }
                values.push(userId);
                const updateQuery = `UPDATE users SET ${fields.join(", ")} WHERE id = $${paramIndex} RETURNING id, email, name, profile_picture_url`;
                const result = await pool.query(updateQuery, values);
                if (result.rows.length === 0) { return h.response({ statusCode: 404, message: "User not found" }).code(404); }
                return h.response({ statusCode: 200, message: "Profile updated successfully", user: result.rows[0] }).code(200);
            } catch (err) {
                console.error("Error updating profile:", err);
                if (err.code === '23505') return h.response({ statusCode: 409, message: "Email already in use" }).code(409);
                return h.response({ statusCode: 500, message: "Internal Server Error" }).code(500);
            }
        },
    });

    // Food Prediction Route
    server.route({
        method: "POST",
        path: "/predict",
        options: {
            validate: {
                headers: Joi.object({ authorization: Joi.string().required() }).unknown(true),
                payload: Joi.object({
                    imageUrl: Joi.string().uri().required(),
                }),
                failAction: (request, h, err) => h.response({ statusCode: 400, message: err.details[0].message }).code(400).takeover(),
            },
        },
        handler: async (request, h) => {
            const decodedToken = verifyToken(request.headers.authorization.substring(7));
            if (!decodedToken) { return h.response({ statusCode: 401, message: "Unauthorized" }).code(401); }
            const { imageUrl } = request.payload;
            try {
                const imageResponse = await axios.get(imageUrl, { responseType: 'arraybuffer' });
                const imageBlob = new Blob([imageResponse.data], { type: imageResponse.headers['content-type'] });
                const app = await GradioClient(HUGGING_FACE_SPACE);
                const result = await app.predict("/predict", { image: imageBlob });
                if (!result || !result.data || !Array.isArray(result.data) || result.data.length < 1) {
                    return h.response({ statusCode: 404, message: "Could not identify the food in the image." }).code(404);
                }
                const rawPredictionString = result.data[0];
                const predictedName = rawPredictionString.split('(')[0].trim();
                const lookupKey = predictedName.toLowerCase().replace(/\s+/g, ' ');
                const recipe = recipes[lookupKey];
                if (!recipe) {
                    console.log(`Lookup failed. Predicted label: "${predictedName}", Normalized key: "${lookupKey}"`);
                    return h.response({ statusCode: 404, message: `Food '${predictedName}' identified, but no recipe is available yet.` }).code(404);
                }
                return h.response({ statusCode: 200, prediction: { label: recipe.name }, recipe: recipe }).code(200);
            } catch (error) {
                console.error("Error during prediction:", error);
                return h.response({ statusCode: 500, message: "An error occurred while processing the image." }).code(500);
            }
        }
    });

    // GENERATE UPLOAD URL
    server.route({
        method: 'POST',
        path: '/generate-upload-signature',
        options: {
            validate: {
                headers: Joi.object({ authorization: Joi.string().required() }).unknown(true),
                // No payload is needed, the signature is generic.
                failAction: (request, h, err) => h.response({ statusCode: 400, message: err.details[0].message }).code(400).takeover(),
            }
        },
        handler: async (request, h) => {
            const decodedToken = verifyToken(request.headers.authorization.substring(7));
            if (!decodedToken) { return h.response({ statusCode: 401, message: "Unauthorized" }).code(401); }

            const timestamp = Math.round((new Date).getTime() / 1000);

            try {
                // Generate the signature for the upload.
                const signature = cloudinary.utils.api_sign_request(
                    { timestamp: timestamp },
                    CLOUDINARY_API_SECRET
                );
                
                return h.response({
                    statusCode: 200,
                    timestamp,
                    signature,
                    apiKey: CLOUDINARY_API_KEY,
                    cloudName: CLOUDINARY_CLOUD_NAME,
                }).code(200);

            } catch (error) {
                console.error("Error generating Cloudinary signature:", error);
                return h.response({ statusCode: 500, message: "Could not generate upload signature." }).code(500);
            }
        }
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