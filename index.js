const Hapi = require("@hapi/hapi");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// In-memory user store (replace with DB in production)
const users = [];
const JWT_SECRET = "your_jwt_secret";

const validateUser = (username, password) => {
  const user = users.find((u) => u.username === username);
  if (!user) return false;
  return bcrypt.compareSync(password, user.password);
};

const init = async () => {
  const server = Hapi.server({
    port: 3000,
    host: "localhost",
  });

  // testing get
  server.route({
    method: "GET",
    path: "/",
    handler: (request, h) => {
      return { message: "Welcome to the Authentication API" };
    },
  });

  // Register
  server.route({
    method: "POST",
    path: "/register",
    options: {
      validate: {
        payload: Joi.object({
          username: Joi.string().min(4).required(),
          password: Joi.string().min(8).required(),
        }),
      },
    },
    handler: (request, h) => {
      const { username, password } = request.payload;
      if (users.find((u) => u.username === username)) {
        return h
          .response({
            statusCode: 400,
            message: "Username already exists",
          })
          .code(400);
      }
      const hashedPassword = bcrypt.hashSync(password, 10);
      users.push({ username, password: hashedPassword });
      return {
        statusCode: 201,
        message: "Username registered successfully",
      };
    },
  });

  // Login
  server.route({
    method: "POST",
    path: "/login",
    options: {
      validate: {
        payload: Joi.object({
          username: Joi.string().required(),
          password: Joi.string().required(),
        }),
      },
    },
    handler: (request, h) => {
      const { username, password } = request.payload;
      const user = users.find((u) => u.username === username);
      if (!user || !bcrypt.compareSync(password, user.password)) {
        return h
          .response({
            statusCode: 401,
            message: "Invalid username or password",
          })
          .code(401);
      }
      const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });
      return {
        token: token,
        message: "Login successfully",
      };
    },
  });

  // Reset Password
  server.route({
    method: "POST",
    path: "/reset-password",
    options: {
      validate: {
        payload: Joi.object({
          username: Joi.string().required(),
          newPassword: Joi.string().min(8).required(),
        }),
      },
    },
    handler: (request, h) => {
      const { username, newPassword } = request.payload;
      const user = users.find((u) => u.username === username);
      if (!user) {
        return h.response({ message: "Username not found" }).code(404);
      }
      user.password = bcrypt.hashSync(newPassword, 10);
      return { message: "Password reset successful" };
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
