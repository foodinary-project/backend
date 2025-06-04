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
    host: "localhost",
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
        const resetLink = `https://your-frontend/reset?email=${encodeURIComponent(
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
          email: Joi.string().email().required(),
          newEmail: Joi.string().email(),
          newName: Joi.string().min(2),
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
    handler: (request, h) => {
      const { email, newEmail, newName, newPassword } = request.payload;
      const user = users.find((u) => u.email === email);
      if (!user) {
        return h
          .response({ statusCode: 404, message: "User not found" })
          .code(404);
      }
      if (newEmail) {
        if (users.find((u) => u.email === newEmail)) {
          return h
            .response({
              statusCode: 400,
              message: "New email already exists",
            })
            .code(400);
        }
        user.email = newEmail;
      }
      if (newName) {
        user.name = newName;
      }
      if (newPassword) {
        user.password = bcrypt.hashSync(newPassword, 10);
      }
      return {
        statusCode: 200,
        message: "Profile updated successfully",
        user: { email: user.email, name: user.name },
      };
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
