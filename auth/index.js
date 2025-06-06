require("dotenv").config();
const Hapi = require("@hapi/hapi");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { Storage } = require("@google-cloud/storage"); // Import GCS library

const users = [];
const resetTokens = {};
const JWT_SECRET = "your_jwt_secret";

// Nodemailer Transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

let storage;
try {
  storage = new Storage();
  console.log("Google Cloud Storage client initialized successfully.");
} catch (error) {
  console.error("Failed to initialize Google Cloud Storage client:", error);
  // You might want to prevent the server from starting if GCS is essential
  // process.exit(1);
}

const GCS_BUCKET_NAME = process.env.GCS_BUCKET_NAME; // Get your bucket name from environment variables

// --- Helper Functions ---
const verifyToken = (token) => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded;
  } catch (err) {
    return null;
  }
};

// --- Server Initialization ---
const init = async () => {
  if (!GCS_BUCKET_NAME) {
    console.error(
      "GCS_BUCKET_NAME environment variable is not set. Please set it to your GCS bucket name."
    );
    // process.exit(1); // Optionally exit if the bucket name isn't configured
  }
  if (!storage && GCS_BUCKET_NAME) {
    // Only try to use storage if it was initialized and bucket name is present
    console.warn(
      "GCS Storage client not available, but bucket name is set. Signed URL generation will fail."
    );
  }

  const server = Hapi.server({
    port: process.env.PORT || 3000,
    host: process.env.HOST || "0.0.0.0",
    routes: {
      cors: {
        origin: [
          "http://localhost:3000",
          "http://localhost:3001",
          "http://localhost:8080",
          "http://localhost:5173",
          "http://localhost:4200",
          // Add your deployed frontend origin here for production
        ],
        headers: [
          "Accept",
          "Authorization",
          "Content-Type",
          "If-None-Match",
          "X-File-Name",
          "X-File-Type",
        ], // Added X-File-Name and X-File-Type
        credentials: true,
      },
    },
  });

  // --- Authentication Routes (Register, Login, Reset Password, Update Profile) ---
  // Ensure profilePictureUrl is handled as a URL string.

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
      users.push({
        email,
        name,
        password: hashedPassword,
        profilePictureUrl: null,
      });
      return {
        statusCode: 201,
        message: "User registered successfully",
      };
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
        failAction: (request, h, err) => {
          return h
            .response({ statusCode: 400, message: err.details[0].message })
            .code(400)
            .takeover();
        },
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
        user: {
          email: user.email,
          name: user.name,
          profilePictureUrl: user.profilePictureUrl || null,
        },
      };
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
        failAction: (request, h, err) => {
          return h
            .response({ statusCode: 400, message: err.details[0].message })
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
        // Requesting reset link
        const resetToken = crypto.randomBytes(32).toString("hex");
        const expires = Date.now() + 1000 * 60 * 15; // 15 minutes
        resetTokens[email] = { token: resetToken, expires };
        const resetLink = `${
          process.env.FRONTEND_URL || "http://localhost:8080"
        }/reset-password?email=${encodeURIComponent(
          email
        )}&token=${resetToken}`; // Use your frontend URL
        try {
          await transporter.sendMail({
            from: `"Your App Name" <${process.env.GMAIL_USER}>`,
            to: email,
            subject: "Password Reset Request",
            text: `Click the following link to reset your password: ${resetLink}\nThis link will expire in 15 minutes.`,
            html: `<p>Click the following link to reset your password:</p><p><a href="${resetLink}">${resetLink}</a></p><p>This link will expire in 15 minutes.</p>`,
          });
          return { message: "Password reset link sent to your email" };
        } catch (err) {
          console.error("Failed to send reset email:", err);
          return h
            .response({
              message: "Failed to send reset email",
              error: err.message,
            })
            .code(500);
        }
      } else if (token && newPassword) {
        // Submitting new password with token
        const record = resetTokens[email];
        if (!record || record.token !== token || record.expires < Date.now()) {
          return h
            .response({ message: "Invalid or expired reset token" })
            .code(400);
        }
        user.password = bcrypt.hashSync(newPassword, 10);
        delete resetTokens[email]; // Invalidate the token
        return { message: "Password reset successful" };
      }
      return h.response({ message: "Invalid request payload" }).code(400);
    },
  });

  // UPDATE PROFILE
  server.route({
    method: "PUT",
    path: "/update-profile",
    options: {
      validate: {
        headers: Joi.object({
          authorization: Joi.string().required(), // Expect JWT in Authorization header
        }).unknown(true),
        payload: Joi.object({
          // email field is no longer needed in payload if identifying user by JWT
          newEmail: Joi.string().email().optional(),
          newName: Joi.string().min(2).optional(),
          newPassword: Joi.string()
            .min(8)
            .pattern(new RegExp("^(?=.*[A-Z])(?=.*\\d).+$"))
            .optional()
            .messages({
              "string.pattern.base":
                "Password must contain at least one uppercase letter and one number",
            }),
          newProfilePictureUrl: Joi.string().uri().allow(null, "").optional(),
        }),
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
      const token =
        authHeader && authHeader.startsWith("Bearer ")
          ? authHeader.substring(7)
          : null;
      const decodedToken = token ? verifyToken(token) : null;

      if (!decodedToken || !decodedToken.email) {
        return h
          .response({ statusCode: 401, message: "Invalid or expired token" })
          .code(401);
      }

      const currentUserEmail = decodedToken.email;
      const { newEmail, newName, newPassword, newProfilePictureUrl } =
        request.payload;
      const userIndex = users.findIndex((u) => u.email === currentUserEmail);

      if (userIndex === -1) {
        return h
          .response({ statusCode: 404, message: "User not found" })
          .code(404);
      }

      const userToUpdate = users[userIndex];

      if (newEmail && newEmail !== userToUpdate.email) {
        if (
          users.some((u, index) => u.email === newEmail && index !== userIndex)
        ) {
          return h
            .response({ statusCode: 400, message: "New email already exists" })
            .code(400);
        }
        userToUpdate.email = newEmail;
        // If email changes, you might want to issue a new JWT reflecting this change.
      }
      if (newName) {
        userToUpdate.name = newName;
      }
      if (newPassword) {
        userToUpdate.password = bcrypt.hashSync(newPassword, 10);
      }
      if (newProfilePictureUrl !== undefined) {
        userToUpdate.profilePictureUrl = newProfilePictureUrl;
      }

      users[userIndex] = userToUpdate; // Persist changes (in-memory)

      return {
        statusCode: 200,
        message: "Profile updated successfully",
        user: {
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

  // --- NEW: Route to generate a GCS Signed URL for uploading ---
  server.route({
    method: "POST",
    path: "/generate-upload-url",
    options: {
      validate: {
        headers: Joi.object({
          // Ensure user is authenticated
          authorization: Joi.string().required(),
        }).unknown(true),
        payload: Joi.object({
          fileName: Joi.string().required(), // e.g., "profile-pic.jpg"
          contentType: Joi.string().required(), // e.g., "image/jpeg"
        }),
        failAction: (request, h, err) => {
          return h
            .response({ statusCode: 400, message: err.details[0].message })
            .code(400)
            .takeover();
        },
      },
    },
    handler: async (request, h) => {
      if (!storage || !GCS_BUCKET_NAME) {
        console.error("GCS not configured for signed URL generation.");
        return h
          .response({
            statusCode: 500,
            message: "Cloud storage not configured on server.",
          })
          .code(500);
      }

      const authHeader = request.headers.authorization;
      const token =
        authHeader && authHeader.startsWith("Bearer ")
          ? authHeader.substring(7)
          : null;
      const decodedToken = token ? verifyToken(token) : null;

      if (!decodedToken || !decodedToken.email) {
        return h
          .response({
            statusCode: 401,
            message: "Unauthorized: Invalid or expired token",
          })
          .code(401);
      }
      // Optional: You could use decodedToken.email to create user-specific paths in GCS

      const { fileName, contentType } = request.payload;
      const uniqueFileName = `${crypto
        .randomBytes(8)
        .toString("hex")}-${Date.now()}-${fileName.replace(/\s+/g, "_")}`; // Create a more unique file name

      // Define options for the signed URL
      const options = {
        version: "v4", // Use v4 signing process
        action: "write", // Allow writing (uploading) the file
        expires: Date.now() + 15 * 60 * 1000, // URL expires in 15 minutes
        contentType: contentType, // The content type of the file to be uploaded
      };

      try {
        // Get a v4 signed URL for uploading file
        const [url] = await storage
          .bucket(GCS_BUCKET_NAME)
          .file(uniqueFileName) // The name the file will have in GCS
          .getSignedUrl(options);

        return h
          .response({
            statusCode: 200,
            message: "Signed URL generated successfully.",
            uploadUrl: url, // The URL frontend will use to PUT the file
            publicUrl: `https://storage.googleapis.com/${GCS_BUCKET_NAME}/${uniqueFileName}`, // The URL to store in DB after upload
          })
          .code(200);
      } catch (error) {
        console.error("Failed to generate signed URL:", error);
        return h
          .response({
            statusCode: 500,
            message: "Failed to generate upload URL.",
            error: error.message,
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

process.on("unhandledRejection", (err) => {
  console.error("Unhandled Rejection:", err);
  // It's often better to let the process crash on unhandled rejections
  // so that process managers (like PM2, Docker) can restart it.
  // process.exit(1);
});

init();
