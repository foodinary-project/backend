require("dotenv").config();
const Hapi = require("@hapi/hapi");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const users = [];
const resetTokens = {}; // In-memory store for reset tokens
const JWT_SECRET = "your_jwt_secret";

// Configure Nodemailer transporter (Gmail SMTP)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

const validateUser = (email, password) => {
  const user = users.find((u) => u.email === email);
  if (!user) return false;
  return bcrypt.compareSync(password, user.password);
};

const init = async () => {
  const server = Hapi.server({
    port: 3000,
    host: process.env.HOST || "0.0.0.0",
    routes: {
      // ADD THIS SECTION FOR CORS
      cors: {
        origin: [
          "http://localhost:3000", // Common frontend port, adjust if needed
          "http://localhost:3001", // Another common frontend port
          "http://localhost:8080", // Another common frontend port
          "http://localhost:5173", // Common for Vite
          "http://localhost:4200", // Common for Angular
          // Add any other ports your frontend team uses for development
        ],
        headers: ["Accept", "Authorization", "Content-Type", "If-None-Match"], // Ensure "Authorization" is listed if you use Bearer tokens
        credentials: true, // If your frontend needs to send cookies or use Authorization headers
      },
    },
  });

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
        failAction: (request, h, err) => {
          return h
            .response({
              statusCode: 400,
              message: err.details[0].message,
            })
            .code(400)
            .takeover();
        },
      },
    },
    handler: (request, h) => {
      const { email, name, password } = request.payload;
      if (users.find((u) => u.email === email)) {
        return h
          .response({
            statusCode: 400,
            message: "Email already exists",
          })
          .code(400);
      }
      const hashedPassword = bcrypt.hashSync(password, 10);
      users.push({ email, name, password: hashedPassword });
      return {
        statusCode: 201,
        message: "User registered successfully",
      };
    },
  });

  server.route({
    method: "POST",
    path: "/login",
    options: {
      validate: {
        payload: Joi.object({
          email: Joi.string().email().required(),
          password: Joi.string().required(),
        }),
      },
    },
    handler: (request, h) => {
      const { email, password } = request.payload;
      const user = users.find((u) => u.email === email);
      if (!user || !bcrypt.compareSync(password, user.password)) {
        return h
          .response({
            statusCode: 401,
            message: "Invalid email or password",
          })
          .code(401);
      }
      const token = jwt.sign({ email, name: user.name }, JWT_SECRET, {
        expiresIn: "1h",
      });
      return {
        token: token,
        message: "Login successfully",
        user: { email: user.email, name: user.name },
      };
    },
  });

  server.route({
    method: "POST",
    path: "/reset-password",
    options: {
      validate: {
        payload: Joi.object({
          email: Joi.string().email().required(),
          token: Joi.string(),
          newPassword: Joi.string()
            .min(8)
            .pattern(new RegExp("^(?=.*[A-Z])(?=.*\\d).+$"))
            .messages({
              "string.pattern.base":
                "Password must contain at least one uppercase letter and one number",
            }),
        }),
        failAction: (request, h, err) => {
          return h
            .response({
              statusCode: 400,
              message: err.details[0].message,
            })
            .code(400)
            .takeover();
        },
      },
    },
    handler: async (request, h) => {
      const { email, token, newPassword } = request.payload;
      const user = users.find((u) => u.email === email);
      if (!user) {
        return h.response({ message: "Email not found" }).code(404);
      }
      if (!token && !newPassword) {
        const resetToken = crypto.randomBytes(32).toString("hex");
        const expires = Date.now() + 1000 * 60 * 15; // 15 minutes
        resetTokens[email] = { token: resetToken, expires };
        const resetLink = `https://backend-4lij.onrender.com/reset-password?email=${encodeURIComponent(
          email
        )}&token=${resetToken}`;
        try {
          await transporter.sendMail({
            from: '"Foodinary | Find Your Traditional Indonesian Food!" <foodinary.project@gmail.com>',
            to: email,
            subject: "Password Reset Request",
            text: `Click the following link to reset your password: ${resetLink}\nThis link will expire in 15 minutes.`,
            html: `<p>Click the following link to reset your password:</p><p><a href="${resetLink}">${resetLink}</a></p><p>This link will expire in 15 minutes.</p>`,
          });
        } catch (err) {
          return h
            .response({
              message: "Failed to send reset email",
              error: err.message,
            })
            .code(500);
        }
        return { message: "Password reset link sent to your email" };
      }
      if (token && newPassword) {
        const record = resetTokens[email];
        if (!record || record.token !== token || record.expires < Date.now()) {
          return h
            .response({ message: "Invalid or expired reset token" })
            .code(400);
        }
        user.password = bcrypt.hashSync(newPassword, 10);
        delete resetTokens[email];
        return { message: "Password reset successful" };
      }
      return h.response({ message: "Invalid request" }).code(400);
    },
  });

  server.route({
    method: "PUT",
    path: "/update-profile",
    options: {
      validate: {
        payload: Joi.object({
          email: Joi.string().email().required(), // Current email to identify the user
          newEmail: Joi.string().email(), // Optional: new email
          newName: Joi.string().min(2), // Optional: new name
          newPassword: Joi.string() // Optional: new password
            .min(8)
            .pattern(new RegExp("^(?=.*[A-Z])(?=.*\\d).+$"))
            .messages({
              "string.pattern.base":
                "Password must contain at least one uppercase letter and one number",
            }),
          newProfilePictureUrl: Joi.string().uri().allow(null, "").optional(), // ADDED: Optional, allow URL, null, or empty string
        }),
        failAction: (request, h, err) => {
          return h
            .response({
              statusCode: 400,
              message: err.details[0].message,
            })
            .code(400)
            .takeover();
        },
      },
    },
    handler: (request, h) => {
      const { email, newEmail, newName, newPassword, newProfilePictureUrl } =
        request.payload; // DESTRUCTURE newProfilePictureUrl

      const userIndex = users.findIndex((u) => u.email === email); // Find index to modify directly in the array

      if (userIndex === -1) {
        return h
          .response({ statusCode: 404, message: "User not found" })
          .code(404);
      }

      // Get a reference to the user object to modify
      const userToUpdate = users[userIndex];

      if (newEmail && newEmail !== userToUpdate.email) {
        // Check if newEmail is different before checking for existence
        if (
          users.find((u, index) => u.email === newEmail && index !== userIndex)
        ) {
          // Ensure new email isn't taken by another user
          return h
            .response({
              statusCode: 400,
              message: "New email already exists",
            })
            .code(400);
        }
        userToUpdate.email = newEmail;
      }
      if (newName) {
        userToUpdate.name = newName;
      }
      if (newPassword) {
        userToUpdate.password = bcrypt.hashSync(newPassword, 10);
      }

      // ADDED: Update profile picture URL if provided
      // The `undefined` check is important because if the field is not in the payload, it will be undefined.
      // Joi's `optional()` means it might not be there. `allow(null, '')` means it could be explicitly set to null or empty.
      if (newProfilePictureUrl !== undefined) {
        userToUpdate.profilePictureUrl = newProfilePictureUrl;
      }

      // Update the user in the array (though direct modification above already does this for objects)
      users[userIndex] = userToUpdate;

      return {
        statusCode: 200,
        message: "Profile updated successfully",
        user: {
          // Return the updated user details
          email: userToUpdate.email,
          name: userToUpdate.name,
          profilePictureUrl: userToUpdate.profilePictureUrl,
        },
      };
    },
  });

  server.route({
    method: "GET",
    path: "/profile",
    options: {
      handler: (request, h) => {
        const authHeader = request.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
          return h
            .response({ statusCode: 401, message: "Missing or invalid token" })
            .code(401);
        }

        const token = authHeader.substring(7); // Remove "Bearer " prefix
        const decodedToken = verifyToken(token);

        if (!decodedToken || !decodedToken.email) {
          return h
            .response({ statusCode: 401, message: "Invalid or expired token" })
            .code(401);
        }

        const user = users.find((u) => u.email === decodedToken.email);
        if (!user) {
          // This case should ideally not happen if the token is valid and user exists
          return h
            .response({ statusCode: 404, message: "User not found" })
            .code(404);
        }

        // For now, profilePictureUrl is null.
        // You'll need to modify user registration/update to include this.
        return h
          .response({
            statusCode: 200,
            message: "Profile retrieved successfully",
            user: {
              email: user.email,
              name: user.name,
              profilePictureUrl: user.profilePictureUrl || null, // Assuming you add this field to your user object
            },
          })
          .code(200);
      },
    },
  });

  await server.start();
  console.log("Server running on %s", server.info.uri);
};

process.on("unhandledRejection", (err) => {
  console.log(err);
  process.exit(1);
});

init();
